#ifndef __SPFS_MANAGER_MOUNT_H_
#define __SPFS_MANAGER_MOUNT_H_

#include <stddef.h>

struct spfs_manager_context_s;

int mount_fs(int sock, struct spfs_manager_context_s *ctx, void *package, size_t psize);

#endif
