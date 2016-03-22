#ifndef __SPFS_INTERFACE_H_
#define __SPFS_INTERFACE_H_

#include <sys/stat.h>
#include <string.h>

enum {
	FUSE_PROXY_MODE,
	FUSE_STUB_MODE,
	FUSE_GOLEM_MODE,
	FUSE_MAX_MODE,
};

struct external_cmd {
	unsigned int	cmd;
	unsigned long	pad;
	char		ctx[0];
};

struct cmd_package_s {
	int		mode;
	char		path[0];
};

struct dentry_package_s {
	struct stat	stat;
	char		path[0];
};

enum {
	FUSE_CMD_SET_MODE,
	FUSE_CMD_INSTALL_PATH,
	FUSE_CMD_MAX,
};

static inline size_t path_packet_size(const char *path)
{
	return sizeof(struct external_cmd) + sizeof(struct dentry_package_s) + strlen(path) + 1;
}

static inline size_t mode_packet_size(const char *path)
{
	return sizeof(struct external_cmd) + sizeof(struct cmd_package_s) + strlen(path) + 1;
}

static inline void fill_path_packet(struct external_cmd *package,
		      const char *path, const struct stat *stat)
{
	struct dentry_package_s *dp = (struct dentry_package_s *)&package->ctx;

	package->cmd = FUSE_CMD_INSTALL_PATH;

	memcpy(&dp->stat, stat, sizeof(dp->stat));
	strcpy(dp->path, path);
}

static inline void fill_mode_packet(struct external_cmd *package, unsigned mode,
			const char *path)
{
	struct cmd_package_s *cp = (struct cmd_package_s *)&package->ctx;

	package->cmd = FUSE_CMD_SET_MODE;

	cp->mode = mode;
	strcpy(cp->path, path);
}

extern int spfs_conn_handler(int sock, void *data);

#endif
