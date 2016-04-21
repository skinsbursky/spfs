#ifndef __SPFS_MANAGER_MOUNT_H_
#define __SPFS_MANAGER_MOUNT_H_

#include <stddef.h>

struct spfs_manager_context_s;
struct spfs_info_s;

int replace_mount(int sock, struct spfs_info_s *info,
		  const char *source, const char *fstype,
		  const char *mountflags, const char *freeze_cgroup,
		  const void *options);

#endif
