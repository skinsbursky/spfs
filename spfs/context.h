#ifndef __SPFS_CONTEXT_H_
#define __SPFS_CONTEXT_H_

#include <stdio.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <pthread.h>

#include "include/list.h"

#include "interface.h"

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
	char                    *proxy_dir;
	int			proxy_root_fd;
};

struct spfs_context_s {
	struct work_mode_s	*wm;
	pthread_mutex_t		wm_lock;

	FILE			*log;
	struct fuse_operations	*operations[SPFS_MAX_MODE];

	struct dentry_info_s	root;
	pthread_mutex_t		root_lock;

	int			packet_socket;
	struct sockaddr_un	sock_addr;
	pthread_t		sock_pthread;
};

int context_init(const char *proxy_dir, int mode, const char *log_file,
		 const char *socket_path, int verbosity);
int context_store_mnt_stat(const char *mountpoint);

void context_fini(void);

struct spfs_context_s *get_context(void);
const struct fuse_operations *get_operations(struct work_mode_s *wm);

int change_work_mode(struct spfs_context_s *ctx, int mode, const char *path);
int set_work_mode(struct spfs_context_s *ctx, int mode, const char *path);
int wait_mode_change(int current_mode);

const struct work_mode_s *ctx_work_mode(void);
int copy_work_mode(struct work_mode_s **wm);
void destroy_work_mode(struct work_mode_s *wm);
int stale_work_mode(int mode, const char *proxy_dir);

#endif
