#ifndef __SPFS_MANAGER_MOUNT_H_
#define __SPFS_MANAGER_MOUNT_H_

#include <stddef.h>

struct spfs_manager_context_s;
struct spfs_info_s;

int prepare_mount_env(struct spfs_info_s *info, const char *proxy_dir);
int cleanup_mount_env(struct spfs_info_s *info);

int replace_spfs(int sock, struct spfs_info_s *info,
		  const char *source, const char *fstype,
		  const char *mountflags, const void *options);

#endif
