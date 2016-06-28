#include "spfs_config.h"

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
#include "freeze.h"
#include "replace.h"
#include "cgroup.h"

int create_spfs_info(const char *id, const char *mountpoint,
		     pid_t ns_pid, const char *root,
		     int *mgr_ns_fds, const char *ovz_id,
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

	info->ovz_id = ovz_id;
	info->mgr_ns_fds = mgr_ns_fds;

	info->mode = SPFS_REPLACE_MODE_HOLD;

	*i = info;

	return 0;
}

static bool spfs_pid_match(const struct mount_info_s *mnt, const void *data)
{
	pid_t pid = (pid_t)(unsigned long)data;
	const struct spfs_info_s *info = container_of(mnt, const struct spfs_info_s, mnt);

	return info->pid == pid;
}

static bool spfs_replacer_match(const struct mount_info_s *mnt, const void *data)
{
	pid_t pid = (pid_t)(unsigned long)data;
	const struct spfs_info_s *info = container_of(mnt, const struct spfs_info_s, mnt);

	return info->replacer == pid;
}

struct spfs_info_s *find_spfs_by_pid(struct shared_list *mounts, pid_t pid)
{
	struct mount_info_s *mnt;

	mnt = iterate_mounts(mounts, (void *)(unsigned long)pid, spfs_pid_match);
	if (mnt)
		return container_of(mnt, struct spfs_info_s, mnt);
	return NULL;
}

struct spfs_info_s *find_spfs_by_replacer(struct shared_list *mounts, pid_t pid)
{
	struct mount_info_s *mnt;

	mnt = iterate_mounts(mounts, (void *)(unsigned long)pid, spfs_replacer_match);
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
	close_namespaces(info->ns_fds);
}

int spfs_chroot(const struct spfs_info_s *info)
{
	struct stat st;

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

static int join_spfs_context(const struct spfs_info_s *info, int ns_mask)
{
	int err;

	if (info->ns_pid) {
		err = set_namespaces(info->ns_fds, ns_mask);
		if (err)
			return err;
	}

	err = spfs_chroot(info);

	if (err && info->ns_pid)
		(void) set_namespaces(info->mgr_ns_fds, ns_mask);
	return err;
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

static int __spfs_prepare_env(struct spfs_info_s *info, const char *proxy_dir)
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
	int err, res;

	res = join_spfs_context(info, NS_MNT_MASK);
	if (res)
		return res;

	err = __spfs_prepare_env(info, proxy_dir);

	res = set_namespaces(info->mgr_ns_fds, NS_MNT_MASK);

	return err ? err : res;
}

static int __spfs_cleanup_env(struct spfs_info_s *info)
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
	int err, res;

	res = join_spfs_context(info, NS_MNT_MASK);
	if (res)
		return res;

	err = __spfs_cleanup_env(info);

	res = set_namespaces(info->mgr_ns_fds, NS_MNT_MASK);

	return err ? err : res;
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

static int __do_replace_spfs_mounts(struct spfs_info_s *info, const char *source)
{
	int err;
	struct spfs_bindmount *bm;
	struct mount_info_s *mnt = &info->mnt;

	err = lock_shared_list(&info->mountpaths);
	if (err) {
		pr_err("failed to lock info %s mount paths list\n", mnt->id);
		return err;
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
	return err;
}

static int do_replace_spfs_mounts(struct spfs_info_s *info, const char *source)
{
	int err, res;

	res = join_spfs_context(info, NS_MNT_MASK);
	if (res)
		return res;

	err = __do_replace_spfs_mounts(info, source);

	res = set_namespaces(info->mgr_ns_fds, NS_MNT_MASK);

	return err ? err : res;
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

	err = do_replace_spfs_mounts(info, source);
	if (!err)
		err = __replace_resources(info->fg, info->ns_fds, NULL,
					  mnt->st.st_dev, info->mnt_ref,
					  mnt->mountpoint);

	res = spfs_thaw_and_unlock(info);

	return err ? err : res;
}

static int __do_mount_target(struct spfs_info_s *info,
		const char *source, const char *target, const char *fstype,
		long mflags, const void *options)
{
	int err, res;

	res = join_spfs_context(info, NS_MNT_MASK | NS_NET_MASK |
				      NS_USER_MASK | NS_UTS_MASK);
	if (res)
		return res;

	err = create_dir(target);
	if (err) {
		pr_err("failed to create mountpoint %s\n", target);
		return err;
	}

	return mount_loop(source, target, fstype, mflags, options);
}

static int do_mount_target(struct spfs_info_s *info,
		const char *source, const char *target, const char *fstype,
		long mflags, const void *options)
{
	int err, status;
	pid_t pid;

	/* One may ask, why we fork here is pid nemespace is not required?
	 * The reason is that we can't change UTS ns back, is nested UTS ns
	 * doesn't have CAP_SYS_ADMIN (which is common).
	 * While we want to keep current environment sane. */

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			return -errno;
		case 0:
			_exit(__do_mount_target(info, source, target, fstype,
						mflags, options));
	}

	err = collect_child(pid, &status, 0);

	return err ? err : status;
}

int replace_spfs(int sock, struct spfs_info_s *info,
		  const char *source, const char *fstype,
		  const char *mountflags, const void *options)
{
	char *mnt;
	int err;
	long mflags;

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

	err = xatol(mountflags, &mflags);
	if (err)
		goto free_mnt;

	err = do_mount_target(info, source, mnt, fstype, mflags, options);
	if (err)
		goto free_mnt;

	err = spfs_send_mode(info, SPFS_PROXY_MODE, mnt);
	if (err)
		/*TODO: should umount the target ? */
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

static int exec_spfs(int pipe, const struct spfs_info_s *info, const char *mode,
		     const char *proxy_dir, const char *socket_path, const char *log_path,
		     const char *mountpoint)
{
	const char *spfs = FS_NAME;
	char wpipe[16];
	char **options;
	int err;

	sprintf(wpipe, "%d", pipe);

	options = exec_options(0, "spfs", "-vvvv", "-f", "--single-user",
				"-o", "no_remote_lock",
				"--mode", mode,
				"--socket-path", socket_path,
				"--ready-fd", wpipe,
				"--log", log_path,
				mountpoint, NULL);
	if (options && strlen(info->root))
		options = add_exec_options(options, "--root", info->root, NULL);
	if (options && proxy_dir)
		options = add_exec_options(options, "--proxy-dir", proxy_dir, NULL);

	if (!options)
		return -ENOMEM;

	if (info->ns_pid) {
		err = set_namespaces(info->ns_fds, NS_MNT_MASK | NS_NET_MASK |
				NS_USER_MASK | NS_UTS_MASK);
		if (err)
			goto free_options;
	}

	err = execvp_print(spfs, options);

free_options:
	free(options);
	return err;
}

int do_mount_spfs(struct spfs_info_s *info,
		  const char *mode, const char *proxy_dir,
		  int pipe_fd)
{
	char *cwd, *socket_path, *log_path, *mountpoint, *dir;
	int err = -ENOMEM;

	cwd = get_current_dir_name();
	if (!cwd) {
		pr_perror("failed to get cwd");
		return -ENOMEM;
	}

	mountpoint = xsprintf("%s%s", info->root, info->mnt.mountpoint);
	if (!mountpoint)
		goto free_cwd;

	socket_path = xsprintf("%s/%s", cwd, info->socket_path);
	if (!socket_path)
		goto free_mountpoint;

	log_path = xsprintf("%s/spfs-%s.log", cwd, info->mnt.id);
	if (!log_path)
		goto free_socket_path;

	if (strcmp(mode, "restore"))
		dir = strdup(proxy_dir);
	else {
		mode = "proxy";
		dir = xsprintf("%s/restore", info->work_dir);
	}
	if (!dir) {
		pr_perror("failed to allocate\n");
		goto free_log_path;
	}

	err = spfs_prepare_env(info, dir);
	if (err)
		goto free_proxy_dir;

	err = exec_spfs(pipe_fd, info, mode,
			dir, socket_path, log_path, mountpoint);

free_proxy_dir:
	free(dir);
free_log_path:
	free(log_path);
free_socket_path:
	free(socket_path);
free_mountpoint:
	free(mountpoint);
free_cwd:
	free(cwd);
	return err;
}

int update_spfs_info(struct spfs_info_s *info)
{
	struct mount_info_s *mnt = &info->mnt;
	int err, res;

	info->sock = seqpacket_sock(info->socket_path, true, false, NULL);
	if (info->sock < 0) {
		pr_err("failed to connect to spfs with id %s\n", mnt->id);
		return info->sock;
	}

	res = join_spfs_context(info, NS_MNT_MASK);
	if (res)
		return res;

	err = stat(mnt->mountpoint, &mnt->st);
	if (err) {
		pr_perror("failed to stat spfs %s mount point (%s)", mnt->id,
				mnt->mountpoint);
		err = -errno;
		goto set_orig_ns;
	}

	info->mnt_ref = open(mnt->mountpoint, O_PATH);
	if (info->mnt_ref < 0) {
		pr_perror("failed to open %s", mnt->mountpoint);
		err = -errno;
	}

set_orig_ns:
	res = set_namespaces(info->mgr_ns_fds, NS_MNT_MASK);

	return err ? err : res;
}

int release_spfs_info(struct spfs_info_s *info)
{
	close(info->sock);
	return 0;
}

int umount_spfs(struct spfs_info_s *info)
{
	struct mount_info_s *mnt = &info->mnt;
	int err, res;

	res = join_spfs_context(info, NS_MNT_MASK);
	if (res)
		return res;

	err = umount(info->mnt.mountpoint);
	if (err) {
		pr_perror("failed to unmount spfs %s (%s)", mnt->id,
				mnt->mountpoint);
		err = -errno;
	}
	if (!err)
		err = __spfs_cleanup_env(info);

	res = set_namespaces(info->mgr_ns_fds, NS_MNT_MASK);

	return err ? err : res;
}
