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

static int mount_loop(struct spfs_info_s *info,
		      const char *source, const char *mnt,
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

static int do_replace_spfs_frozen(struct spfs_info_s *info, const char *source)
{
	int err;
	struct spfs_bindmount *bm;
	int spfs_ref;

	spfs_ref = open(info->mountpoint, O_RDONLY | O_DIRECTORY);
	if (spfs_ref < 0) {
		pr_perror("failed to open %s", info->mountpoint);
		return spfs_ref;
	}

	err = lock_shared_list(&info->mountpaths);
	if (err) {
		pr_err("failed to lock info %s mount paths list\n", info->id);
		goto close_spfs_ref;
	}

	list_for_each_entry(bm, &info->mountpaths.list, list) {
		if (do_replace_one_spfs(source, bm->path)) {
			pr_err("failed to replace %s by %s\n", bm->path, source);
		}
	}

	(void) unlock_shared_list(&info->mountpaths);

close_spfs_ref:
	close(spfs_ref);
	return err;
}

static int do_replace_spfs(struct spfs_info_s *info, const char *source)
{
	int err;

	err = spfs_freeze_ct(info);
	if (err)
		return err;

	err = ct_run(do_replace_spfs_frozen, info, source);

	if (spfs_thaw_ct(info))
		return -1;

	return spfs_send_mode(info, SPFS_PROXY_MODE, info->mountpoint);
}

static int umount_target(const struct spfs_info_s *info, const char *mnt)
{
	pr_debug("Unmounting %s\n", mnt);

	if (umount2(mnt, MNT_DETACH)) {
		pr_perror("failed to umount %s", mnt);
		return -1;
	}
	return 0;
}

static int do_mount_target(struct spfs_info_s *info,
		const char *source, const char *target, const char *fstype,
		const char *mountflags, const void *options)
{
	int err, mode = SPFS_PROXY_MODE;
	long mflags;

	err = xatol(mountflags, &mflags);
	if (err)
		return err;

	err = ct_run(mount_loop, info, source, target, fstype, mflags, options);
	if (err)
		return err;

	err = spfs_send_mode(info, mode, target);
	if (err)
		/*TODO: should umount the target ? */
		return err;

	return 0;
}


static int do_replace_mount(struct spfs_info_s *info, int sock,
		const char *source, const char *fstype,
		const char *mountflags, const void *options)
{
	char *mnt;
	int err;

	(void) send_status(sock, 0);

	mnt = xsprintf("%s/%s", info->work_dir, fstype);
	if (!mnt) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	err = do_mount_target(info, source, mnt,
			fstype, mountflags, options);
	if (err)
		goto free_mnt;

	err = do_replace_spfs(info, mnt);
	if (err)
		goto free_mnt;

	(void) ct_run(umount_target, info, mnt);

free_mnt:
	free(mnt);
	return err;
}

int replace_mount(int sock, struct spfs_info_s *info,
		  const char *source, const char *fstype,
		  const char *mountflags, const void *options)
{
	return do_replace_mount(info, sock, source, fstype, mountflags, options);
}
