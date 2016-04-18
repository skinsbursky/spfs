#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <fcntl.h>

#include "include/util.h"
#include "include/log.h"
#include "include/socket.h"

#include "spfs/context.h"

#include "context.h"
#include "interface.h"
#include "mount.h"
#include "spfs.h"
#include "freeze.h"

static int do_mount(const char *source, const char *mnt,
		    const char *fstype, unsigned long mountflags,
		    const void *options)
{
	int err;

	err = mount(source, mnt, fstype, mountflags, options);
	if (!err)
		return 0;

	switch (errno) {
		case EPROTONOSUPPORT:
		case EPERM:
			pr_warn("failed to mount %s to %s: %s\n", fstype, mnt,
					strerror(errno));
			return -EAGAIN;
	}
	return -errno;
}

static int mount_loop(const char *source, const char *mnt,
		      const char *fstype, unsigned long mountflags,
		      const void *options)
{
	int err = 0;
	int timeout = 1;

	while (1) {
		err = do_mount(source, mnt, fstype, mountflags, options);
		if (err != -EAGAIN)
			break;

		pr_warn("retrying in %d seconds\n", timeout);
		sleep(timeout);

		if (timeout < 32)
			timeout <<= 1;
	}

	if (err) {
		pr_perror("failed to mount %s to %s", fstype, mnt);
		goto rmdir_mnt;
	}

	pr_info("Successfully mounted %s to %s\n", fstype, mnt);

	return 0;

rmdir_mnt:
	if (rmdir(mnt))
		pr_perror("failed to remove %s", mnt);
	return err;

}

static int do_replace_mount(const struct spfs_info_s *info, const char *source,
			    const char *freeze_cgroup)
{
	int pid, status;
	int err;

	err = lock_cgroup_and_freeze(info->fg);
	if (err)
		return err;

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			err = -errno;
			goto thaw_cgroup;
		case 0:
			if (enter_spfs_context(info))
				_exit(EXIT_FAILURE);

			err = umount2(info->mountpoint, MNT_DETACH);
			if (err) {
				pr_perror("failed to umount %s", info->mountpoint);
				_exit(EXIT_FAILURE);
			}

			pr_debug("mountpoint %s was lazily umounted\n", info->mountpoint);

			err = mount(source, info->mountpoint, NULL, MS_BIND, NULL);
			if (err) {
				pr_perror("failed to bind-mount %s to %s", source, info->mountpoint);
				_exit(EXIT_FAILURE);
			}

			pr_debug("mountpoint %s was bind-mounted to %s\n", source, info->mountpoint);
			_exit(EXIT_SUCCESS);
	}

	err = collect_child(pid, &status, 0);
	if (!err)
		err = status;

thaw_cgroup:
	if (thaw_cgroup_and_unlock(info->fg))
		return -1;
	return err ? err : status;
}

static int umount_target(const struct spfs_info_s *info, const char *mnt)
{
	int pid, err, status;

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			return -errno;
		case 0:
			if (enter_spfs_context(info))
				_exit(EXIT_FAILURE);

			if (umount2(mnt, MNT_DETACH)) {
				pr_perror("failed to umount %s");
				_exit(EXIT_FAILURE);
			}
			_exit(EXIT_SUCCESS);
	}

	err = collect_child(pid, &status, 0);

	return err ? err : status;
}

static int mount_target(int sock, const struct spfs_info_s *info,
			const char *source, const char *mnt, const char *fstype,
			long mountflags, const void *options)
{
	int pid, err, status;

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			return -errno;
		case 0:
			if (enter_spfs_context(info))
				_exit(EXIT_FAILURE);

			(void) send_status(sock, 0);

			_exit(mount_loop(source, mnt, fstype, mountflags, options));
	}

	err = collect_child(pid, &status, 0);

	return err ? err : status;
}

int replace_mount(int sock, const struct spfs_info_s *info,
		  const char *source, const char *fstype,
		  const char *mountflags, const char *freeze_cgroup,
		  const void *options)
{
	char *mnt;
	int err = -1, mode = SPFS_PROXY_MODE;
	long mflags;
	int spfs_ref;

	err = xatol(mountflags, &mflags);
	if (err)
		return err;

	mnt = xsprintf("%s/%s", info->work_dir, fstype);
	if (!mnt) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	if (create_dir("%s%s", info->root, mnt)) {
		pr_err("failed to create mountpoint %s\n", mnt);
		goto free_mnt;
	}

	err = mount_target(sock, info, source, mnt, fstype, mflags, options);
	if (err)
		goto free_mnt;

	pr_debug("successfully mounted %s to %s\n", fstype, mnt);

	err = spfs_send_mode(info->sock, mode, mnt);
	if (err) {
		pr_err("failed to switch spfs to proxy mode to %s: %d\n", mnt,
				err);
		goto free_mnt;
	}

	pr_debug("spfs mode was changed to %d (path: %s)\n", mode, mnt);

	spfs_ref = open(info->mountpoint, O_RDONLY | O_DIRECTORY);
	if (spfs_ref < 0) {
		pr_perror("failed to open %s", info->mountpoint);
		goto free_mnt;
	}

	err = do_replace_mount(info, mnt, freeze_cgroup);
	if (err) {
		pr_err("failed to replace mounts\n");
		goto close_spfs_ref;
	}

	pr_debug("mountpoint %s replaced %s\n", mnt, info->mountpoint);

	err = spfs_send_mode(info->sock, mode, info->mountpoint);
	if (err) {
		pr_err("failed to switch spfs to proxy mode to %s: %d\n",
					info->mountpoint, err);
		goto close_spfs_ref;
	}

	pr_debug("spfs mode was changed to %d (path: %s)\n", mode,
				info->mountpoint);

	pr_debug("Unmounting %s\n", mnt);

	(void) umount_target(info, mnt);

close_spfs_ref:
	close(spfs_ref);
free_mnt:
	free(mnt);
	return err;
}
