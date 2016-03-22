#include "spfs_config.h"

#include <unistd.h>
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <linux/futex.h>
#include <syscall.h>

#include "include/util.h"
#include "include/context.h"
#include "include/log.h"

#define UNIX_SEQPACKET

extern struct fuse_operations stub_operations;
extern struct fuse_operations proxy_operations;
extern struct fuse_operations golem_operations;

extern int create_socket_interface(struct context_data_s *ctx, const char *socket_path);
extern int start_socket_thread(struct context_data_s *ctx);

struct context_data_s fs_context = {
	.operations		= {
		[FUSE_PROXY_MODE]	= &proxy_operations,
		[FUSE_STUB_MODE]	= &stub_operations,
		[FUSE_GOLEM_MODE]	= &golem_operations,
	},
	.root_lock		= PTHREAD_MUTEX_INITIALIZER,
	.wm_lock		= PTHREAD_MUTEX_INITIALIZER,
	.packet_socket		= -1,
};

const char *work_modes[] = {
	[FUSE_PROXY_MODE]	= "Proxy",
	[FUSE_STUB_MODE]	= "Stub",
	[FUSE_GOLEM_MODE]	= "Golem",
};

struct context_data_s *get_context(void)
{
	return &fs_context;
}

const struct fuse_operations *get_operations(struct work_mode_s *wm)
{
	const struct context_data_s *ctx = get_context();
	const struct fuse_operations *ops;

	switch (wm->mode) {
		case FUSE_PROXY_MODE:
			ops = ctx->operations[FUSE_PROXY_MODE];
			break;
		case FUSE_STUB_MODE:
			ops = ctx->operations[FUSE_STUB_MODE];
			break;
		case FUSE_GOLEM_MODE:
			ops = ctx->operations[FUSE_GOLEM_MODE];
			break;
		default:
			pr_crit("%s: unsupported mode: %d\n", __func__, wm->mode);
			ops = ctx->operations[FUSE_STUB_MODE];
			break;
	}
	return ops;
}

const struct work_mode_s *ctx_work_mode(void)
{
	return get_context()->wm;
}

int wait_mode_change(int current_mode)
{
	int err;

	err = syscall(SYS_futex, &get_context()->wm->mode, FUTEX_WAIT,
		      current_mode, NULL, NULL, 0);
	if (err)
		return err;
	return -ERESTARTSYS;
}

static int wake_mode_waiters(void)
{
	struct context_data_s *ctx = get_context();

	return syscall(SYS_futex, &ctx->wm->mode, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
}

static int create_work_mode(int mode, const char *path, struct work_mode_s **wm)
{
	struct work_mode_s *new;
	int err = -ENOMEM;

	new = malloc(sizeof(*new));
	if (!new) {
		pr_err("%s: failed to allocate work mode structure\n", __func__);
		return -ENOMEM;
	}

	new->mode = mode;
	new->proxy_root_fd = -1;
	new->proxy_dir = NULL;

	if (path ) {
		new->proxy_dir = strdup(path);
		if (!new->proxy_dir) {
			pr_err("%s: failed to allocate proxy_dir for work mode structure\n", __func__);
			goto free_new;
		}
		/* Take a reference to underlying fs to make sure, that
		 * it won't be removed from underneath of us. */
		new->proxy_root_fd = open(new->proxy_dir, O_PATH);
		if (new->proxy_root_fd == -1) {
			pr_perror("Failed to open %s", new->proxy_dir);
			err = -errno;
			goto free_proxy_dir;
		}
	}
	*wm = new;
	return 0;

free_proxy_dir:
	free(new->proxy_dir);
free_new:
	free(new);
	return err;
}

int copy_work_mode(struct work_mode_s **wm)
{
	struct context_data_s *ctx = get_context();
	const struct work_mode_s *ctx_wm;
	struct work_mode_s *copy;
	int err;

	copy = malloc(sizeof(*copy));
	if (!copy)
		return -ENOMEM;

	err = pthread_mutex_lock(&ctx->wm_lock);
	if (err) {
		pr_err("%s: failed to lock wm: %d\n", __func__, err);
		return -err;
	}

	ctx_wm = ctx->wm;

	if (ctx_wm->proxy_dir) {
		copy->proxy_dir = strdup(ctx_wm->proxy_dir);
		if (!copy->proxy_dir)
			goto free_copy;
	}
	copy->mode = ctx_wm->mode;
	copy->proxy_root_fd = -1;

        pthread_mutex_unlock(&ctx->wm_lock);

	*wm = copy;
	return 0;

free_copy:
        pthread_mutex_unlock(&ctx->wm_lock);
	free(copy);
	return -ENOMEM;
}

void destroy_work_mode(struct work_mode_s *wm)
{
	if (!wm)
		return;
	if (wm->proxy_root_fd != -1)
		close(wm->proxy_root_fd);
	if (wm->proxy_dir)
		free(wm->proxy_dir);
	free(wm);
}

int stale_work_mode(int mode, const char *proxy_dir)
{
	struct context_data_s *ctx = get_context();

	if (mode != ctx->wm->mode)
		return 1;

	return !!strcmp(proxy_dir, ctx->wm->proxy_dir);
}

int set_work_mode(struct context_data_s *ctx, int mode, const char *path)
{
	struct work_mode_s *cur_wm = get_context()->wm;
	struct work_mode_s *new_wm = NULL;
	int err;

	switch (mode) {
		case FUSE_PROXY_MODE:
		case FUSE_GOLEM_MODE:
		case FUSE_STUB_MODE:
			err = create_work_mode(mode, path, &new_wm);
			if (err)
				return err;

			err = pthread_mutex_lock(&ctx->wm_lock);
			if (err) {
				pr_err("%s: failed to lock wm: %d\n", __func__, err);
				free(new_wm);
				return -err;
			}
			get_context()->wm = new_wm;
		        pthread_mutex_unlock(&ctx->wm_lock);

			destroy_work_mode(cur_wm);
			break;
		default:
			pr_err("%s: unsupported mode: %d\n", mode);
			return -EINVAL;
	}
	wake_mode_waiters();
	return 0;
}

int change_work_mode(struct context_data_s *ctx, int mode, const char *path)
{
	pr_info("%s: changing work mode from %d to %d (path: %s)\n", __func__, ctx->wm->mode, mode, path);
	if (!stale_work_mode(mode, path)) {
		pr_info("%s: the mode is already %d\n", __func__, ctx->wm->mode);
		return 0;
	}
	return set_work_mode(ctx, mode, path);
}


static int setup_context(struct context_data_s *ctx, const char *proxy_dir,
			 int mode)
{
	int err = -ENOMEM;

	ctx->root.name = strdup("/");
	if (!ctx->root.name) {
		pr_err("%s: failed to duplicate string\n", __func__);
		return -ENOMEM;
	}

	err = set_work_mode(ctx, mode, proxy_dir);
	if (err) {
		pr_err("Set work mode %d failed\n", mode);
		return err;
	}

	INIT_LIST_HEAD(&ctx->root.children);
	INIT_LIST_HEAD(&ctx->root.siblings);
	ctx->root.parent = &ctx->root;

	return 0;
}

static int setup_log(struct context_data_s *ctx, const char *log_file, int verbosity)
{
	int fd;

	fd = open(log_file, O_CREAT | O_TRUNC | O_RDWR);
	if (fd < 0) {
		pr_perror("%s: failed to open log file", __func__);
		return -errno;
	}
	pr_debug("Log fd: %d\n", fd);
	fd = save_fd(fd);
	if (fd < 0) {
		pr_crit("Failed to save log fd\n");
		return fd;
	}
	pr_debug("Saved log fd: %d\n", fd);
	ctx->log = fdopen(fd, "w+");
	if (!ctx->log) {
		pr_perror("failed to open log stream");
		close(fd);
		return -errno;
	}
	setvbuf(ctx->log, NULL, _IONBF, 0);
	init_log(ctx->log, verbosity);
	return 0;
}

int context_store_mnt_stat(const char *mountpoint)
{
	struct context_data_s *ctx = get_context();
	int err;

	if (!mountpoint) {
		pr_crit("%s: mountpoint wasn't specified\n", __func__);
		return -EINVAL;
	}

	err = stat(mountpoint, &get_context()->root.stat);
	if (err < 0) {
		pr_crit("%s: failed to stat %s\n", __func__, ctx->wm->proxy_dir);
		return err;
	}
	return 0;
}

int context_init(const char *proxy_dir, int mode, const char *log_file,
		 const char *socket_path, int verbosity)
{
	struct context_data_s *ctx = get_context();
	int err;

	pr_debug("fuse: opening log %s\n", log_file);

	err = setup_log(ctx, log_file, verbosity);
	if (err) {
		pr_crit("Failed to open log: %d\n", err);
		return err;
	}

	pr_debug("fuse: creating context\n");
	pr_debug("%s: log         : %s\n", __func__, log_file);
	pr_debug("%s: socket path : %s\n", __func__, socket_path);
	pr_debug("%s: verbosity   : +%d\n", __func__, verbosity);

	err = setup_context(ctx, proxy_dir, mode);
	if (err) {
		pr_crit("Failed to setup context: %d\n", err);
		return err;
	}

	pr_debug("%s: proxy_dir   : %s\n", __func__, ctx->wm->proxy_dir);
	pr_debug("%s: mode        : %s\n", __func__, work_modes[ctx->wm->mode]);

	err = create_socket_interface(ctx, socket_path);
	if (err) {
		pr_err("failed to create socket interface: %d\n", err);
		return err;
	}

	return start_socket_thread(ctx);
}

void context_fini(void)
{
	struct context_data_s *ctx = get_context();
	void *res;
	int err;

	pr_info("shutting down context\n");

	err = pthread_cancel(ctx->sock_pthread);
	if (!err) {
		err = pthread_join(ctx->sock_pthread, &res);
		if (err)
			pr_err("failed to join socket thread: %d\n", err);
	} else
		pr_err("failed to kill socket thread: %d\n", err);

	if (close(ctx->packet_socket))
		pr_perror("failed to close pthread socket");

	if (unlink(ctx->sock_addr.sun_path))
		pr_perror("failed to unlink %s", ctx->sock_addr.sun_path);

}
