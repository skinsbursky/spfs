#include "errno.h"
#include <stdlib.h>

#include "include/log.h"
#include "include/shm.h"
#include "include/util.h"
#include "include/socket.h"

#include "spfs.h"
#include "context.h"
#include "freeze.h"

static struct spfs_info_s *__find_spfs_by_id(struct shared_list *mounts, const char *id)
{
	struct spfs_info_s *info;

	list_for_each_entry(info, &mounts->list, list) {
		if (!strcmp(info->id, id))
			return info;
	}

	return NULL;
}

struct spfs_info_s *find_spfs_by_id(struct shared_list *mounts, const char *id)
{
	struct spfs_info_s *info = NULL;

	if (lock_shared_list(mounts))
		return NULL;

	info = __find_spfs_by_id(mounts, id);

	(void) unlock_shared_list(mounts);

	return info;
}

struct spfs_info_s *__find_spfs_by_pid(struct shared_list *mounts, pid_t pid)
{
	struct spfs_info_s *info;

	list_for_each_entry(info, &mounts->list, list) {
		if (info->pid == pid)
			return info;
	}

	return NULL;
}

struct spfs_info_s *find_spfs_by_pid(struct shared_list *mounts, pid_t pid)
{
	struct spfs_info_s *info = NULL;

	if (lock_shared_list(mounts))
		return NULL;

	info = __find_spfs_by_pid(mounts, pid);

	(void) unlock_shared_list(mounts);

	return info;
}

int add_spfs_info(struct shared_list *mounts, struct spfs_info_s *info)
{
	int err = 0;

	if (lock_shared_list(mounts))
		return -EINVAL;

	if (__find_spfs_by_id(mounts, info->id)) {
		pr_err("spfs info with id %s already exists\n", info->id);
		err = -EEXIST;
	} else {
		pr_info("added info with id %s\n", info->id);
		list_add_tail(&info->list, &mounts->list);
	}

	(void) unlock_shared_list(mounts);

	return err;
}

void del_spfs_info(struct shared_list *mounts, struct spfs_info_s *info)
{
	if (!lock_shared_list(mounts)) {
		list_del(&info->list);
		(void) unlock_shared_list(mounts);
	}
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
					info->id, path);
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
	pr_debug("added mount path %s to spfs info %s\n", bm->path, info->id);
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
		pr_err("failed to lock info %s bind mounts list\n", info->id);
		goto free_bm_array;
	}

        while ((bm = strsep(&bm_array, ",")) != NULL) {
		if (!strlen(bm))
			continue;
		err = __spfs_add_one_mountpath(info, bm);
		if (err && (err != -EEXIST)) {
			pr_err("failed to add bind-mount %s to info %s\n",
					bm, info->id);
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

	pr_debug("changing spfs %s mode to %d (path: %s)\n", info->id, mode,
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
				info->id, proxy_dir, err);
	else
		pr_debug("spfs %s mode was changed to %d (path: %s)\n",
				info->id, mode, proxy_dir);

	free(package);
	return err;
}

int spfs_freeze_and_lock(struct spfs_info_s *info)
{
	if (info->fg) {
		pr_debug("Freeze %s and lock in favor of spfs %s\n", info->fg->path, info->id);
		return lock_cgroup_and_freeze(info->fg);
	}
	return 0;
}

int spfs_thaw_and_unlock(struct spfs_info_s *info)
{
	if (info->fg) {
		pr_debug("Thaw %s and unlock in favor of spfs %s\n", info->fg->path, info->id);
		return thaw_cgroup_and_unlock(info->fg);
	}
	return 0;
}
