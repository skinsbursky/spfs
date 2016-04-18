#include "errno.h"

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

	if ((st.st_dev == info->root_stat.st_dev) ||
	    (st.st_ino == info->root_stat.st_ino)) {
		pr_debug("root is already %s\n", info->root);
		return 0;
	}

	/* Ok, let's try to change root. And, probably, we shouldn't care
	 * either it ours or not. */
	return secure_chroot(info->root);
}
