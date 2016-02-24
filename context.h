#ifndef __CONTEXT_FUSE_FS_H_
#define __CONTEXT_FUSE_FS_H_

#include <stdio.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <pthread.h>

#include "list.h"

#define ERESTARTSYS		512

enum {
	FUSE_PROXY_MODE,
	FUSE_STUB_MODE,
	FUSE_GOLEM_MODE,
	FUSE_MAX_MODE,
};

struct dentry_info_s {
	char   *name;
	struct stat	 stat;
	struct list_head children;
	struct list_head siblings;
};

struct context_data_s {
	const char		*proxy_dir;
	FILE			*log;
	int			mode;
	struct fuse_operations	*operations[FUSE_MAX_MODE];

	struct dentry_info_s	root;
	pthread_mutex_t		root_lock;
	int			packet_socket;
	struct sockaddr_un	sock_addr;
	pthread_t		sock_pthread;
};

int context_init(const char *root, const char *proxy_dir,
		 int mode, const char *log_file, const char *socket_path,
		 int verbosity);

void context_fini(void);

struct context_data_s *get_context(void);

int set_work_mode(struct context_data_s *ctx, int mode);
int wait_mode_change(int current_mode);

const struct fuse_operations *get_operations(void);

#endif
