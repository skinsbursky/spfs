#ifndef __SPFS_MANAGER_FREEZE_H_
#define __SPFS_MANAGER_FREEZE_H_

#include <unistd.h>
#include <semaphore.h>

#include "include/list.h"

struct shared_list;

struct freeze_cgroup_s {
	struct list_head	list;
	char			*path;
	sem_t			sem;
};

struct freeze_cgroup_s *get_freeze_cgroup(struct shared_list *list, const char *path);

int lock_cgroup(struct freeze_cgroup_s *fg);
int unlock_cgroup(struct freeze_cgroup_s *fg);
int thaw_cgroup(const struct freeze_cgroup_s *fg);
int freeze_cgroup(const struct freeze_cgroup_s *fg);

int open_cgroup_state(const struct freeze_cgroup_s *fg);

int cgroup_pids(const struct freeze_cgroup_s *fg, char **list);

#endif
