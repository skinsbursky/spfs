#ifndef __SPFS_MANAGER_INTERFACE_H_
#define __SPFS_MANAGER_INTERFACE_H_

#include "spfs/interface.h"

typedef enum {
	SPFS_MANAGER_MOUNT_FS = SPFS_CMD_MAX,
	SPFS_MANAGER_CMD_MAX,
} spfs_manager_cmd_t;

struct mount_fs_package_s {
	unsigned long	mountflags;
	char		mountdata[0];
};

static inline size_t mount_packet_size(const char *source, const char *type,
				       const char *options)
{
	return sizeof(struct external_cmd) + sizeof(struct mount_fs_package_s) +
			strlen(source) + strlen(type) + strlen(options) + 2 + 1;
}

static inline void fill_mount_packet(struct external_cmd *package,
		      const char *source, const char *type, const char *options,
		      unsigned long mountflags)
{
	struct mount_fs_package_s *dp = (struct mount_fs_package_s *)&package->ctx;

	package->cmd = SPFS_MANAGER_MOUNT_FS;

	dp->mountflags = mountflags;
	sprintf(dp->mountdata, "%s;%s;%s", source, type, options);
}

int spfs_send_mode(int sock, spfs_mode_t mode, const char *path_to_send);

#endif
