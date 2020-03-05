#include "spfs_config.h"

#include <stdlib.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <limits.h>
#include <stdbool.h>

#include "include/log.h"
#include "include/util.h"
#include "include/socket.h"
#include "include/futex.h"
#include "include/namespaces.h"

#include "spfs/xattr.h"

#include "spfs.h"
#include "freeze.h"
#include "replace.h"
#include "cgroup.h"
#include "context.h"
#include "processes.h"

int create_spfs_info(const char *id,
		     const char *mountpoint, const char *ns_mountpoint,
		     pid_t ns_pid, const char *root, struct spfs_info_s **i)
{
	struct spfs_info_s *info;
	int err;

	if (!ns_mountpoint)
		ns_mountpoint = mountpoint;

	info = shm_alloc(sizeof(*info));
	if (!info) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	err = init_mount_info(&info->mnt, id, mountpoint, ns_mountpoint);
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

	err = spfs_add_mount_paths(info, ns_mountpoint);
	if (err)
		return err;

	INIT_LIST_HEAD(&info->mnt.list);
	INIT_LIST_HEAD(&info->processes);

	info->mode = SPFS_REPLACE_MODE_HOLD;
	info->replacer = -1;

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

static int leave_spfs_context(const struct spfs_info_s *info, int ns_mask)
{
	int err;

	err = set_namespaces(mgr_ns_fds(), ns_mask);
	if (err)
		return err;

	err = chdir(mgr_work_dir());
	if (err) {
		pr_perror("failed to chdir to %s\n", mgr_work_dir());
		return -errno;
	}

	return 0;
}

static int join_spfs_context(const struct spfs_info_s *info,
			     unsigned ns_mask, unsigned *orig_ns_mask)
{
	int err;

	*orig_ns_mask = 0;

	if (info->ns_pid) {
		err = join_namespaces(info->ns_fds, ns_mask, orig_ns_mask);
		if (err)
			return err;
	}

	err = spfs_chroot(info);

	if (err && info->ns_pid)
		(void) leave_spfs_context(info, *orig_ns_mask);
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
		   spfs_mode_t mode, const char *proxy_dir, int ns_pid)
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
	fill_mode_packet(package, mode, proxy_dir, ns_pid);

	err = seqpacket_sock_send(info->sock, package, psize);
	if (err)
		pr_err("failed to switch spfs %s to %s mode to %s (ns_pid: %d): %d\n",
				info->mnt.id, mode, proxy_dir, ns_pid, err);
	else
		pr_info("spfs %s mode was changed to %d (path: %s, ns_pid: %d)\n",
				info->mnt.id, mode, proxy_dir, ns_pid);

	free(package);
	return err;
}

static int spfs_freeze_and_lock(struct spfs_info_s *info)
{
	struct freeze_cgroup_s *fg = info->fg;
	int err = 0;

	if (fg) {
		pr_info("freeze %s and lock in favor of spfs %s\n",
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
		pr_info("thaw %s and unlock in favor of spfs %s\n",
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
	unsigned orig_ns_mask;

	res = join_spfs_context(info, NS_MNT_MASK, &orig_ns_mask);
	if (res)
		return res;

	err = __spfs_prepare_env(info, proxy_dir);

	res = leave_spfs_context(info, orig_ns_mask);

	return err ? err : res;
}

static int __spfs_cleanup_env(struct spfs_info_s *info, bool failed)
{
	if (failed && umount(info->work_dir)) {
		pr_perror("failed to umount %s", info->work_dir);
		return -errno;
	}

	if (rmdir(info->work_dir)) {
		pr_perror("failed to remove directory %s", info->work_dir);
		return -errno;
	}
	return 0;
}

int spfs_cleanup_env(struct spfs_info_s *info, bool failed)
{
	int err, res;
	unsigned orig_ns_mask;

	res = join_spfs_context(info, NS_MNT_MASK, &orig_ns_mask);
	if (res)
		return res;

	err = __spfs_cleanup_env(info, failed);

	res = leave_spfs_context(info, orig_ns_mask);

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

static int cleanup_mountpoint(const char *mnt)
{
	pr_info("unmounting %s\n", mnt);

	if (umount2(mnt, MNT_DETACH)) {
		pr_perror("failed to umount %s", mnt);
		return -errno;
	}

	if (rmdir(mnt)) {
		pr_perror("failed to remove directory %s", mnt);
		return -errno;
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

	err = spfs_send_mode(info, SPFS_PROXY_MODE,
			     mnt->ns_mountpoint, info->ns_pid);
	if (!err)
		(void) cleanup_mountpoint(source);

unlock_shared_list:
	(void) unlock_shared_list(&info->mountpaths);
	return err;
}

static int do_replace_spfs_mounts(struct spfs_info_s *info, const char *source)
{
	int err, res;
	unsigned orig_ns_mask;

	res = join_spfs_context(info, NS_MNT_MASK, &orig_ns_mask);
	if (res)
		return res;

	err = __do_replace_spfs_mounts(info, source);

	res = leave_spfs_context(info, orig_ns_mask);

	return err ? err : res;
}

static int do_replace_spfs_resources(struct spfs_info_s *info)
{
	struct mount_info_s *mnt = &info->mnt;

	return __replace_resources(info->fg, info->ns_fds, NULL,
				   mnt->st.st_dev,
				   info->mnt_ref, info->mnt_id,
				   mnt->ns_mountpoint);
}

static int do_replace_spfs(struct spfs_info_s *info, const char *source)
{
	int err, res;

	if (mgr_ovz_id()) {
		err = move_to_cgroup("ve", "/");
		if (err)
			return err;
	}

	res = spfs_freeze_and_lock(info);
	if (res)
		return res;

	/* TODO: this should be done in a different way:
	 * 1) Place target FS on top of spfs.
	 * 2) Do resources collection.
	 * 3) If succeeded, unmount both and place target back.
	 * 4) Do resources swap.
	 * 5) If failed - unmount only target.
	 *
	 * This will allow to keep access stable and repeat the sequence.
	 * But what to do, if failed to repalce
	 */
	err = do_replace_spfs_mounts(info, source);
	if (!err)
		err = do_replace_spfs_resources(info);

	res = spfs_thaw_and_unlock(info);

	return err ? err : res;
}

static int __do_mount_target(struct spfs_info_s *info,
		const char *source, const char *target, const char *fstype,
		long mflags, const void *options)
{
	int err, res;
	unsigned orig_ns_mask;

	res = join_spfs_context(info, NS_MNT_MASK | NS_NET_MASK |
				      NS_USER_MASK | NS_UTS_MASK,
				      &orig_ns_mask);
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

	err = spfs_send_mode(info, SPFS_PROXY_MODE, mnt, info->ns_pid);
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
		     bool no_readahead,
		     const char *mountpoint)
{
	const char *spfs = FS_NAME;
	char wpipe[16];
	char **options;
	int err;

	sprintf(wpipe, "%d", pipe);

	options = exec_options(0, "spfs", "-vv", "-f", "--single-user",
				"-o", "no_remote_lock",
				"-o", "nonempty",
				"-o", "intr",
				"--mode", mode,
				"--socket-path", socket_path,
				"--ready-fd", wpipe,
				"--log", log_path,
				mountpoint, NULL);
	if (options && strlen(info->root))
		options = add_exec_options(options, "--root", info->root, NULL);
	if (options && proxy_dir)
		options = add_exec_options(options, "--proxy-dir", proxy_dir, NULL);
	if (options && no_readahead)
		options = add_exec_options(options, "-o", "max_readahead=0", NULL);
	if (options && info->ns_pid) {
		char pid[32];

		sprintf(pid, "%ld", info->ns_pid);

		options = add_exec_options(options, "--mntns-pid", pid, NULL);
		if (options && proxy_dir)
			options = add_exec_options(options, "--proxy-mntns-pid", pid, NULL);
	}

	if (!options)
		return -ENOMEM;

	err = execvp_print(spfs, options);

	free(options);
	return err;
}

int do_mount_spfs(struct spfs_info_s *info, const char *log_dir,
		  const char *mode, const char *proxy_dir,
		  int pipe_fd)
{
	char *cwd, *socket_path, *log_path, *mountpoint, *dir;
	int err = -ENOMEM;
	bool no_readahead = false;

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

	log_path = xsprintf("%s/spfs-%s.log", log_dir ? log_dir : cwd, info->mnt.id);
	if (!log_path)
		goto free_socket_path;

	if (strcmp(mode, "restore"))
		dir = strdup(proxy_dir);
	else {
		mode = "proxy";
		dir = xsprintf("%s/restore", info->work_dir);
		no_readahead = true;
	}
	if (!dir) {
		pr_perror("failed to allocate\n");
		goto free_log_path;
	}

	err = spfs_prepare_env(info, dir);
	if (err)
		goto free_proxy_dir;

	err = exec_spfs(pipe_fd, info, mode, dir, socket_path, log_path,
			no_readahead, mountpoint);

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
	unsigned orig_ns_mask;

	info->sock = seqpacket_sock(info->socket_path, true, false, NULL);
	if (info->sock < 0) {
		pr_err("failed to connect to spfs with id %s\n", mnt->id);
		return info->sock;
	}

	res = join_spfs_context(info, NS_MNT_MASK, &orig_ns_mask);
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

	info->mnt_id = pid_fd_mnt_id(getpid(), info->mnt_ref);
	if (info->mnt_id < 0) {
		pr_perror("failed to get spfs %s mount ID %s", mnt->id);
		err = info->mnt_id;
	}

set_orig_ns:
	res = leave_spfs_context(info, orig_ns_mask);

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
	unsigned orig_ns_mask;

	res = join_spfs_context(info, NS_MNT_MASK, &orig_ns_mask);
	if (res)
		return res;

	err = umount(info->mnt.mountpoint);
	if (err) {
		pr_perror("failed to unmount spfs %s (%s)", mnt->id,
				mnt->mountpoint);
		err = -errno;
	}
	if (!err)
		err = __spfs_cleanup_env(info, true);

	res = leave_spfs_context(info, orig_ns_mask);

	return err ? err : res;
}

int spfs_link_remap(int mnt_fd, const char *rel_path, char *link_remap, size_t size)
{
	char path[PATH_MAX], *cwd;
	int err = 0;

	cwd = getcwd(path, PATH_MAX);
	if (!cwd) {
		pr_perror("failed to get cwd");
		return -errno;
	}

	/* Why it's done via fchdir, when there if fgetxattr?
	 * Because we need to open an fd otherwise. And it can be not only
	 * regular file, but fifo. ANd it doesn't make sense to bring stat and
	 * various "open" call for different file types here.
	 */
	if (fchdir(mnt_fd)) {
		pr_perror("failed to chdir to mnt_fd %d", mnt_fd);
		return -errno;
	}

	if (getxattr(rel_path, SPFS_XATTR_LINK_REMAP, link_remap, size) < 0) {
		err = -errno;
		if ((errno != ENODATA) && (errno != ENOTSUP))
			pr_perror("failed to get xattr %s for %s",
					SPFS_XATTR_LINK_REMAP, rel_path);
		if (err == -ENOTSUP)
			err = -ENODATA;
	}

	if (chdir(cwd)) {
		pr_perror("failed to chdir to %s", cwd);
		return -errno;
	}

	return err;

}

void spfs_release_mnt(struct spfs_info_s *info)
{
	pr_info("releasing spfs %s mount reference\n", info->mnt.id);
	close(info->mnt_ref);
}
