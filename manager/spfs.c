#include "errno.h"
#include <stdlib.h>

#include "include/log.h"
#include "include/shm.h"
#include "include/util.h"

#include "spfs.h"
#include "context.h"

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
			pr_err("info %s already has bind mount with path %s\n",
					info->id, path);
			return -EEXIST;
		}
	}

	bm = shm_alloc(sizeof(*bm));
	if (!bm) {
		pr_err("failed to allocate bindmount structure\n");
		return -ENOMEM;
	}
	bm->path = shm_alloc(strlen(path) + 1);
	if (!bm->path) {
		pr_err("failed to allocate bindmount path\n");
		return -ENOMEM;
	}
	strcpy(bm->path, path);
	list_add_tail(&bm->list, &info->mountpaths.list);
	pr_debug("added bind-mount path %s to spfs info %s\n", bm->path, info->id);
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
