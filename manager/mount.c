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
#include "include/shm.h"

#include "spfs/context.h"

#include "context.h"
#include "interface.h"
#include "mount.h"
#include "spfs.h"
#include "freeze.h"

#define ct_run(func, info, ...)							\
({										\
	int _pid, _err, _status;						\
										\
	_pid = fork();								\
	switch (_pid) {								\
		case -1:							\
			pr_perror("failed to fork");				\
			_err = -errno;						\
		case 0:								\
			_err = enter_spfs_context(info);			\
			if (_err)						\
				_exit(-_err);					\
										\
			_exit(func(info, ##__VA_ARGS__));			\
		default:							\
			_err = 0;						\
	}									\
										\
	if (_pid > 0)								\
		_err = collect_child(_pid, &_status, 0);			\
										\
	_err ? _err : _status;							\
})

static int do_mount(const char *source, const char *mnt,
		    const char *fstype, unsigned long mountflags,
		    const void *options)
{
	int err;

	err = create_dir(mnt);
	if (err) {
		pr_err("failed to create mountpoint %s\n", mnt);
		return err;
	}

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

	pr_debug("trying to mount %s, source %s, flags %ld, options '%s' to %s\n",
			fstype, source, mountflags, options, mnt);
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

static int do_replace_one_spfs(const char *source, const char *target)
{
	int err;

	err = umount2(target, MNT_DETACH);
	if (err) {
		pr_perror("failed to umount %s", target);
		return err;
	}

	pr_debug("mountpoint %s was lazily umounted\n", target);

	err = mount(source, target, NULL, MS_BIND, NULL);
	if (err) {
		pr_perror("failed to bind-mount %s to %s", source, target);
		return err;
	}

	pr_debug("mountpoint %s was bind-mounted to %s\n", source, target);
	return 0;
}

static int do_replace_spfs_frozen(struct spfs_info_s *info, const char *source,
			   const char *freeze_cgroup)
{
	int err;
	struct spfs_bindmount *bm;

	err = lock_shared_list(&info->mountpaths);
	if (err) {
		pr_err("failed to lock info %s mount paths list\n", info->id);
		return err;
	}

	list_for_each_entry(bm, &info->mountpaths.list, list) {
		if (do_replace_one_spfs(source, bm->path)) {
			pr_err("failed to replace %s by %s\n", bm->path, source);
		}
	}

	(void) unlock_shared_list(&info->mountpaths);
	return 0;
}

static int do_replace_spfs(struct spfs_info_s *info, const char *source,
			   const char *freeze_cgroup)
{
	int err;

	err = lock_cgroup_and_freeze(info->fg);
	if (err)
		return err;

	err = do_replace_spfs_frozen(info, source, freeze_cgroup);

	if (thaw_cgroup_and_unlock(info->fg))
		return -1;

	return err;
}

static int umount_target(const struct spfs_info_s *info, const char *mnt)
{
	if (umount2(mnt, MNT_DETACH)) {
		pr_perror("failed to umount %s", mnt);
		return -1;
	}
	return 0;
}

static int do_mount_target(int sock, struct spfs_info_s *info,
		const char *source, const char *target, const char *fstype,
		const char *mountflags, const void *options)
{
	int err, mode = SPFS_PROXY_MODE;
	long mflags;

	err = xatol(mountflags, &mflags);
	if (err)
		return err;

	err = mount_loop(source, target, fstype, mflags, options);
	if (err)
		return err;

	err = spfs_send_mode(info->sock, mode, target);
	if (err) {
		pr_err("failed to switch spfs to proxy mode to %s: %d\n",
				target, err);
		/*TODO: should umount target ? */
		return err;
	}

	pr_debug("spfs mode was changed to %d (path: %s)\n", mode, target);
	return 0;
}


static int do_replace_mount(int sock, struct spfs_info_s *info,
		const char *source, const char *fstype,
		const char *mountflags, const char *freeze_cgroup,
		const void *options)
{
	char *mnt;
	int err = -1, mode = SPFS_PROXY_MODE;
	int spfs_ref;

	mnt = xsprintf("%s/%s", info->work_dir, fstype);
	if (!mnt) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	err = do_mount_target(sock, info, source, mnt,
				fstype, mountflags, options);
	if (err)
		goto free_mnt;

	/*TODO: how to hold the fs  ? */
	spfs_ref = open(info->mountpoint, O_RDONLY | O_DIRECTORY);
	if (spfs_ref < 0) {
		pr_perror("failed to open %s", info->mountpoint);
		goto free_mnt;
	}

	err = do_replace_spfs(info, mnt, freeze_cgroup);
	if (err) {
		pr_err("failed to replace mounts\n");
		goto close_spfs_ref;
	}

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

int replace_mount(int sock, struct spfs_info_s *info,
		  const char *source, const char *fstype,
		  const char *mountflags, const char *freeze_cgroup,
		  const void *options)
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

			_exit(do_replace_mount(sock, info, source, fstype,
						mountflags, freeze_cgroup,
						options));
	}

	err = collect_child(pid, &status, 0);

	return err ? err : status;
}

