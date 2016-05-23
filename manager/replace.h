#ifndef __SPFS_MANAGER_REPLACE_H_
#define __SPFS_MANAGER_REPLACE_H_

#include <stddef.h>

struct mount_info_s;
struct freeze_cgroup_s;

int replace_resources(struct freeze_cgroup_s *fg, struct mount_info_s *mnt,
		      pid_t ns_pid);

#endif
