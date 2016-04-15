#include "errno.h"

#include "include/log.h"
#include "include/shm.h"

#include "spfs.h"

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

