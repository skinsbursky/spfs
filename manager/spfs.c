#include "errno.h"
#include <stdlib.h>

#include "include/log.h"
#include "include/shm.h"
#include "include/util.h"
#include "include/socket.h"

#include "spfs.h"
#include "context.h"
#include "freeze.h"
#include "mount.h"

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

int enter_spfs_context(const struct spfs_info_s *info)
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
	char *bm_array, *bm;

	bm_array = strdup(bind_mounts);
	if (!bm_array) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	err = lock_shared_list(&info->mountpaths);
	if (err) {
		pr_err("failed to lock info %s bind mounts list\n", info->mnt.id);
		goto free_bm_array;
	}

        while ((bm = strsep(&bm_array, ",")) != NULL) {
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

int spfs_freeze_and_lock(struct spfs_info_s *info)
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
	return 0;
}

int spfs_thaw(struct spfs_info_s *info)
{
	struct freeze_cgroup_s *fg = info->fg;

	if (fg) {
		pr_debug("Thaw %s in favor of spfs %s\n", fg->path, info->mnt.id);
		return thaw_cgroup(fg);
	}
	return 0;
}

int spfs_unlock(struct spfs_info_s *info)
{
	struct freeze_cgroup_s *fg = info->fg;

	if (fg) {
		pr_debug("Unlock %s in favor of spfs %s\n", fg->path, info->mnt.id);
		return unlock_cgroup(fg);
	}
	return 0;
}

int spfs_thaw_and_unlock(struct spfs_info_s *info)
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
