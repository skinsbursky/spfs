#ifndef __CONTEXT_FUSE_FS_H_
#define __CONTEXT_FUSE_FS_H_

#include <stdio.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <pthread.h>

#include "interface.h"
#include "list.h"

#define ERESTARTSYS		512

struct dentry_info_s {
	char   *name;
	struct stat	 stat;
	struct dentry_info_s *parent;
	struct list_head children;
	struct list_head siblings;
};

struct work_mode_s {
	int			mode;
};

struct context_data_s {
	char                    *proxy_dir;
	struct work_mode_s	*wm;
	FILE			*log;
	struct fuse_operations	*operations[FUSE_MAX_MODE];

	struct dentry_info_s	root;
	pthread_mutex_t		root_lock;
	int			root_fd;

	int			packet_socket;
	struct sockaddr_un	sock_addr;
	pthread_t		sock_pthread;
};

int context_init(const char *proxy_dir, int mode, const char *log_file,
		 const char *socket_path, int verbosity);
int context_store_mnt_stat(const char *mountpoint);

void context_fini(void);

struct context_data_s *get_context(void);
const struct fuse_operations *get_operations(int mode);

int set_work_mode(struct context_data_s *ctx, int mode, const char *path);
int wait_mode_change(int current_mode);

int ctx_mode(void);

#endif
