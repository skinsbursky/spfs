#ifndef __SPFS_MANAGER_INTERFACE_H_
#define __SPFS_MANAGER_INTERFACE_H_

#include "spfs/interface.h"

enum {
	SPFS_MANAGER_MOUNT_FS = SPFS_CMD_MAX,
	SPFS_MANAGER_CMD_MAX,
};

struct mount_fs_package_s {
	unsigned long	mountflags;
	char		filesystemtype[64];
	char		data[0];
};

#endif
