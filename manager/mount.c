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
#include "swap.h"

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
										\
	if (_pid > 0) {								\
		pr_debug("Created child %d in spfs %s context\n",		\
				_pid, info->id);				\
		_err = collect_child(_pid, &_status, 0);			\
	}									\
	_err ? _err : _status;							\
})

static int get_pids_list_ct(const char *tasks_file, char **list)
{
	char *pids_list, *p;
	int err = -ENOMEM, fd;
	char buf[4096] = { };
	ssize_t bytes;

	fd = open(tasks_file, O_RDONLY);
	if (fd < 0) {
		pr_perror("failed to open %s", tasks_file);
		return -errno;
	}

	pids_list = NULL;
	do {
		bytes = read(fd, buf, sizeof(buf) - 1);
		if (bytes < 0) {
			pr_perror("failed to read %s", tasks_file);
			err = -errno;
			goto free_pids_list;
		}
		buf[bytes] = '\0';
		if (bytes) {
			pids_list = xstrcat(pids_list, "%s", buf);
			if (!pids_list) {
				pr_err("failed to allocate\n");
				goto free_pids_list;
			}
		}
	} while (bytes > 0);

	p = shm_xsprintf(pids_list);
	if (!p) {
		pr_err("failed to allocate\n");
		goto free_pids_list;
	}

	*list = p;
	err = 0;

	pr_debug("Pids list:\n%s\n", *list);

free_pids_list:
	free(pids_list);
	close(fd);
	return err;
}

static int get_pids_list(struct spfs_info_s *info, char **list)
{
	int pid, err, status;
	static char **pids_list;
	char *tasks_file;

	if (pids_list == NULL) {
		pids_list = shm_alloc(sizeof(pids_list));
		if (!pids_list) {
			pr_err("failed to allocate\n");
			return -ENOMEM;
		}
	}

	tasks_file = xsprintf("%s/tasks", info->fg->path);
	if (!tasks_file)
		return -ENOMEM;

	err = join_one_namespace(info->ns_pid, "pid");
	if (err)
		goto free_task_file;

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			err = -errno;
		case 0:
			_exit(get_pids_list_ct(tasks_file, pids_list));
		default:
			err = 0;
	}

	if (pid > 0)
		err = collect_child(pid, &status, 0);

	*list = *pids_list;

free_task_file:
	free(tasks_file);
	return err ? err : status;
}

static int do_swap_files(struct spfs_info_s *info)
{
	char *pids_list;
	int err;

	err = get_pids_list(info, &pids_list);
	if (err)
		return err;

	return ct_run(do_swap_fds, info, pids_list);
}

static int do_swap_mappings(struct spfs_info_s *info)
{
	return 0;
}

static int prepare_mount_env_ct(struct spfs_info_s *info, const char *proxy_dir)
{
	int err;

	err = create_dir("%s", info->work_dir);
	if (err)
		return err;

	if (mount("spfs-manager", info->work_dir, "tmpfs", 0, "size=1m")) {
		pr_err("failed to mount tmpfs to %s", info->work_dir);
		err = -errno;
		goto rm_info_dir;
	}

	if (proxy_dir) {
		err = create_dir(proxy_dir);
		if (err) {
			pr_err("failed to create %s directory\n", proxy_dir);
			goto umount_tmpfs;
		}
	}

	return 0;

umount_tmpfs:
	if (umount(info->work_dir))
		pr_perror("failed to unmount %s", info->work_dir);
rm_info_dir:
	if (rmdir(info->work_dir))
		pr_perror("failed to remove %s", info->work_dir);
	return err;
}

int prepare_mount_env(struct spfs_info_s *info, const char *proxy_dir)
{
	return ct_run(prepare_mount_env_ct, info, proxy_dir);
}

static int cleanup_mount_env_ct(struct spfs_info_s *info)
{
	if (umount(info->work_dir)) {
		pr_perror("failed to umount %s", info->work_dir);
		return -errno;
	}
	if (rmdir(info->work_dir)) {
		pr_perror("failed to remove directory %s", info->work_dir);
		return -errno;
	}
	return 0;
}

int cleanup_mount_env(struct spfs_info_s *info)
{
	return ct_run(cleanup_mount_env_ct, info);
}

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

static int mount_loop(struct spfs_info_s *info,
		      const char *source, const char *mnt,
		      const char *fstype, unsigned long mountflags,
		      const void *options)
{
	int err;
	int timeout = 1;

	pr_debug("trying to mount %s, source %s, flags %ld, options '%s' to %s\n",
			fstype, source, mountflags, options, mnt);

	err = create_dir(mnt);
	if (err) {
		pr_err("failed to create mountpoint %s\n", mnt);
		return err;
	}

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

	if (stat(info->mountpoint, &info->spfs_stat)) {
		pr_perror("failed to stat %s", info->mountpoint);
		return -errno;
	}

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

	err = spfs_freeze_and_lock(info);
	if (err)
		return err;

	err = ct_run(do_replace_spfs_frozen, info, source);

	if (spfs_thaw_and_unlock(info))
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
	int err;

	err = do_replace_mount(info, sock, source, fstype, mountflags, options);
	if (err)
		return err;

	if (!info->fg)
		return 0;

	err = do_swap_files(info);
	if (err) {
		pr_err("failed to swap fds for spfs %s\n", info->id);
		return err;
	}

	err = do_swap_mappings(info);
	if (err)
		pr_err("failed to swap mappings for spfs %s\n", info->id);

	return err;
}
