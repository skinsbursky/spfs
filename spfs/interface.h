#ifndef __SPFS_INTERFACE_H_
#define __SPFS_INTERFACE_H_

#include <sys/stat.h>
#include <string.h>

#include "spfs/context.h"

typedef enum {
	SPFS_CMD_SET_MODE,
	SPFS_CMD_MAX,
} spfs_cmd_t;

struct external_cmd {
	spfs_cmd_t	cmd;
	unsigned long	pad;
	char		ctx[0];
};

struct cmd_package_s {
	spfs_mode_t	mode;
	char		path[0];
};

static inline size_t mode_packet_size(const char *path)
{
	size_t len = path ? (strlen(path) + 1) : 0;

	return len + sizeof(struct external_cmd) + sizeof(struct cmd_package_s);
}

static inline void fill_mode_packet(struct external_cmd *package, spfs_mode_t mode,
			const char *path)
{
	struct cmd_package_s *cp = (struct cmd_package_s *)&package->ctx;

	package->cmd = SPFS_CMD_SET_MODE;

	cp->mode = mode;
	if (path)
		strcpy(cp->path, path);
}

#endif
