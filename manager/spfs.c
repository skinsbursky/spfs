#include <stdlib.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "include/log.h"
#include "include/util.h"
#include "include/socket.h"
#include "include/futex.h"
#include "include/namespaces.h"

#include "spfs.h"
#include "context.h"
#include "freeze.h"
#include "replace.h"
#include "cgroup.h"

void cleanup_spfs_mount(struct spfs_info_s *info, int status)
{
	pr_debug("removing info %s from the list\n", info->mnt.id);
	info->dead = true;
	list_del(&info->mnt.list);
	unlink(info->socket_path);

	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0))
		spfs_cleanup_env(info);

	close_namespaces(info->ns_fds);
}

int create_spfs_info(const char *id, const char *mountpoint,
		     pid_t ns_pid, const char *ns_list, const char *root,
		     struct spfs_info_s **i)
{
	struct spfs_info_s *info;
	int err;

	info = shm_alloc(sizeof(*info));
	if (!info) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	err = init_mount_info(&info->mnt, id, mountpoint);
	if (err)
		return err;

	if (ns_pid > 0) {
		info->ns_pid = ns_pid;
		info->ns_list = shm_xsprintf(ns_list);
		if (!info->ns_list) {
			pr_perror("failed to allocate string\n");
			return -ENOMEM;
		}
		info->ns_fds = shm_alloc(sizeof(int) * NS_MAX);
		if (!info->ns_fds) {
			pr_perror("failed to allocate string\n");
			return -ENOMEM;
		}
		err = open_namespaces(info->ns_pid, info->ns_fds);
		if (err)
			return err;
	}

	if (root) {
		info->root = shm_xsprintf(root);
		if (!info->root) {
			pr_perror("failed to allocate string\n");
			return -ENOMEM;
		}

		if (stat(info->root, &info->root_stat)) {
			pr_perror("failed to stat %s", info->root);
			return -errno;
		}
	} else {
		info->root = shm_alloc(1);
		if (!info->root) {
			pr_perror("failed to allocate string\n");
			return -ENOMEM;
		}
		info->root[0] = '\0';
	}

	/*
	 * SPFS work dir is placed to the root mount.
	 * Would be nice to have it somewhere in /run/..., but in case of CRIU,
	 * /run can not be mounted yet. Thus, our directory can be overmounted
	 * after creation.
	 */
	info->work_dir = shm_xsprintf("/.spfs-%s", info->mnt.id);
	if (!info->work_dir) {
		pr_perror("failed to allocate string\n");
		return -ENOMEM;
	}

	info->socket_path = shm_xsprintf("spfs-%s.sock", info->mnt.id);
	if (!info->socket_path) {
		pr_perror("failed to allocate string\n");
		return -ENOMEM;
	}

	err = init_shared_list(&info->mountpaths);
	if (err)
		return err;

	err = spfs_add_mount_paths(info, info->mnt.mountpoint);
	if (err)
		return err;

	INIT_LIST_HEAD(&info->mnt.list);
	INIT_LIST_HEAD(&info->processes);

	info->mode = SPFS_REPLACE_MODE_HOLD;

	*i = info;

	return 0;
}

static int enter_spfs_context(const struct spfs_info_s *info);

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
				_pid, info->mnt.id);				\
		_err = collect_child(_pid, &_status, 0);			\
	}									\
	_err ? _err : _status;							\
})

static bool spfs_pid_match(const struct mount_info_s *mnt, const void *data)
{
	pid_t pid = (pid_t)(unsigned long)data;
	const struct spfs_info_s *info = container_of(mnt, const struct spfs_info_s, mnt);

	return info->pid == pid;
}

struct spfs_info_s *find_spfs_by_pid(struct shared_list *mounts, pid_t pid)
{
	struct mount_info_s *mnt;

	mnt = iterate_mounts(mounts, (void *)(unsigned long)pid, spfs_pid_match);
	if (mnt)
		return container_of(mnt, struct spfs_info_s, mnt);
	return NULL;
}

struct spfs_info_s *find_spfs_by_id(struct shared_list *mounts, const char *id)
{
	struct mount_info_s *mnt;

	mnt = find_mount_by_id(mounts, id);
	if (mnt)
		return container_of(mnt, struct spfs_info_s, mnt);
	return NULL;
}

int add_spfs_info(struct shared_list *mounts, struct spfs_info_s *info)
{
	return add_mount_info(mounts, &info->mnt);
}

void del_spfs_info(struct shared_list *mounts, struct spfs_info_s *info)
{
	del_mount_info(mounts, &info->mnt);
}

static int enter_spfs_context(const struct spfs_info_s *info)
{
	int err;
	struct stat st;

	if (info->ns_pid) {
		err = join_namespaces(info->ns_pid, info->ns_list);
		if (err)
			return err;
	}

	if (!strlen(info->root))
		return 0;

	/* Pivot root can change root of the mount namespace to the desired one.
	 * This is how CRIU works.
	 * Let's first check, whether current root is already the one we need.
	 */
	if (stat("/", &st)) {
		pr_perror("failed to stat /");
		return -errno;
	}

	if ((st.st_dev == info->root_stat.st_dev) &&
	    (st.st_ino == info->root_stat.st_ino)) {
		pr_debug("root is already %s\n", info->root);
		return 0;
	}

	/* Ok, let's try to change root. And, probably, we shouldn't care
	 * either it ours or not. */
	return secure_chroot(info->root);
}

static int __spfs_add_one_mountpath(struct spfs_info_s *info, char *path)
{
	struct spfs_bindmount *bm;

	list_for_each_entry(bm, &info->mountpaths.list, list) {
		if (!strcmp(bm->path, path)) {
			pr_warn("spfs %s already has bind mount with path %s\n",
					info->mnt.id, path);
			return -EEXIST;
		}
	}

	bm = shm_alloc(sizeof(*bm));
	if (!bm) {
		pr_err("failed to allocate bindmount structure\n");
		return -ENOMEM;
	}
	bm->path = shm_xsprintf(path);
	if (!bm->path) {
		pr_err("failed to allocate bindmount path\n");
		return -ENOMEM;
	}
	list_add_tail(&bm->list, &info->mountpaths.list);
	pr_debug("added mount path %s to spfs info %s\n", bm->path, info->mnt.id);
	return 0;
}

int spfs_add_mount_paths(struct spfs_info_s *info, const char *bind_mounts)
{
	int err;
	char *bm_array, *ba, *bm;

	bm_array = ba = strdup(bind_mounts);
	if (!bm_array) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	err = lock_shared_list(&info->mountpaths);
	if (err) {
		pr_err("failed to lock info %s bind mounts list\n", info->mnt.id);
		goto free_bm_array;
	}

        while ((bm = strsep(&ba, ",")) != NULL) {
		if (!strlen(bm))
			continue;
		err = __spfs_add_one_mountpath(info, bm);
		if (err && (err != -EEXIST)) {
			pr_err("failed to add bind-mount %s to info %s\n",
					bm, info->mnt.id);
			break;
		}
		err = 0;
	}

	(void) unlock_shared_list(&info->mountpaths);

free_bm_array:
	free(bm_array);
	return err;
}

int spfs_send_mode(const struct spfs_info_s *info,
		   spfs_mode_t mode, const char *proxy_dir)
{
	size_t psize;
	struct external_cmd *package;
	int err;

	pr_debug("changing spfs %s mode to %d (path: %s)\n", info->mnt.id, mode,
			proxy_dir ? : "none");

	psize = mode_packet_size(proxy_dir);

	package = malloc(psize);
	if (!package) {
		pr_err("failed to allocate package\n");
		return -ENOMEM;
	}
	fill_mode_packet(package, mode, proxy_dir);

	err = seqpacket_sock_send(info->sock, package, psize);
	if (err)
		pr_err("failed to switch spfs %s to proxy mode to %s: %d\n",
				info->mnt.id, proxy_dir, err);
	else
		pr_debug("spfs %s mode was changed to %d (path: %s)\n",
				info->mnt.id, mode, proxy_dir);

	free(package);
	return err;
}

static int spfs_freeze_and_lock(struct spfs_info_s *info)
{
	struct freeze_cgroup_s *fg = info->fg;
	int err = 0;

	if (fg) {
		pr_debug("Freeze %s and lock in favor of spfs %s\n",
				fg->path, info->mnt.id);
		err = lock_cgroup(fg);
		if (!err) {
			err = freeze_cgroup(fg);
			if (err)
				(void) unlock_cgroup(fg);
		}
	}
	return err;
}

static int spfs_thaw_and_unlock(struct spfs_info_s *info)
{
	struct freeze_cgroup_s *fg = info->fg;
	int err = 0;

	if (fg) {
		pr_debug("Thaw %s and unlock in favor of spfs %s\n",
				fg->path, info->mnt.id);
		err = thaw_cgroup(fg);
		if (!err)
			(void) unlock_cgroup(fg);
	}
	return err;
}

static int prepare_mount_env_ct(struct spfs_info_s *info, const char *proxy_dir)
{
	int err;

	err = create_dir("%s", info->work_dir);
	if (err)
		return err;

	if (mount("spfs-manager", info->work_dir, "tmpfs", 0, "size=1m")) {
		pr_perror("failed to mount tmpfs to %s", info->work_dir);
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

int spfs_prepare_env(struct spfs_info_s *info, const char *proxy_dir)
{
	return ct_run(prepare_mount_env_ct, info, proxy_dir);
}

static int cleanup_mount_env_ct(struct spfs_info_s *info)
{
	if (umount2(info->work_dir, MNT_DETACH)) {
		pr_perror("failed to umount %s", info->work_dir);
		return -errno;
	}

	if (rmdir(info->work_dir)) {
		pr_perror("failed to remove directory %s", info->work_dir);
		return -errno;
	}
	return 0;
}

int spfs_cleanup_env(struct spfs_info_s *info)
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

static int umount_target(const char *mnt)
{
	pr_debug("Unmounting %s\n", mnt);

	if (umount2(mnt, MNT_DETACH)) {
		pr_perror("failed to umount %s", mnt);
		return -1;
	}
	return 0;
}

static int do_replace_mounts(struct spfs_info_s *info, const char *source)
{
	int err;
	struct spfs_bindmount *bm;
	struct mount_info_s *mnt = &info->mnt;
	int spfs_ref;

	if (stat(mnt->mountpoint, &mnt->st)) {
		pr_perror("failed to stat %s", mnt->mountpoint);
		return -errno;
	}

	spfs_ref = open(mnt->mountpoint, O_RDONLY | O_DIRECTORY);
	if (spfs_ref < 0) {
		pr_perror("failed to open %s", mnt->mountpoint);
		return spfs_ref;
	}

	err = lock_shared_list(&info->mountpaths);
	if (err) {
		pr_err("failed to lock info %s mount paths list\n", mnt->id);
		goto close_spfs_ref;
	}

	list_for_each_entry(bm, &info->mountpaths.list, list) {
		err = do_replace_one_spfs(source, bm->path);
		if (err) {
			pr_err("failed to replace %s by %s\n", bm->path, source);
			goto unlock_shared_list;
		}
	}

	err = spfs_send_mode(info, SPFS_PROXY_MODE, mnt->mountpoint);
	if (!err)
		(void) umount_target(source);

unlock_shared_list:
	(void) unlock_shared_list(&info->mountpaths);
close_spfs_ref:
	close(spfs_ref);
	return err;
}

static int do_replace_spfs(struct spfs_info_s *info, const char *source)
{
	int err, res;
	struct mount_info_s *mnt = &info->mnt;

	if (info->ovz_id) {
		err = move_to_cgroup("ve", "/");
		if (err)
			return err;
	}

	res = spfs_freeze_and_lock(info);
	if (res)
		return res;

	err = ct_run(do_replace_mounts, info, source);
	if (!err)
		err = __replace_resources(info->fg, NULL, mnt->st.st_dev,
					  mnt->mountpoint, info->ns_pid);

	res = spfs_thaw_and_unlock(info);

	return err ? err : res;
}

static int do_mount_target(struct spfs_info_s *info,
		const char *source, const char *target, const char *fstype,
		const char *mountflags, const void *options)
{
	int err;
	long mflags;

	err = xatol(mountflags, &mflags);
	if (err)
		return err;

	err = ct_run(mount_loop, info, source, target, fstype, mflags, options);
	if (err)
		return err;

	err = spfs_send_mode(info, SPFS_PROXY_MODE, target);
	if (err)
		/*TODO: should umount the target ? */
		return err;

	return 0;
}

int replace_spfs(int sock, struct spfs_info_s *info,
		  const char *source, const char *fstype,
		  const char *mountflags, const void *options)
{
	char *mnt;
	int err;

	(void) send_status(sock, 0);

	if (info->mode == SPFS_REPLACE_MODE_HOLD) {
		pr_info("waiting while spfs %s replace is on hold...\n",
				info->mnt.id);
		err = futex_wait((int *)&info->mode, SPFS_REPLACE_MODE_HOLD, NULL);
		if (err) {
			pr_err("failed to wait replace is released\n");
			return err;
		}
		pr_info("spfs %s replace was released\n", info->mnt.id);
	}

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

free_mnt:
	free(mnt);
	return err;
}

int spfs_apply_replace_mode(struct spfs_info_s *info, spfs_replace_mode_t mode)
{
	int err = 0;

	if (info->mode != mode) {
		info->mode = mode;
		err = futex_wake((int *)&info->mode);
		if (err)
			pr_err("failed to wake info %s replace waiters\n",
					info->mnt.id);
	}
	return err;
}
