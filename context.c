#include "config.h"

#include <unistd.h>
#include <fuse.h>
#include <stdio.h>
#include <limits.h>
#include <linux/futex.h>
#include <syscall.h>

#include "util.h"
#include "context.h"
#include "log.h"

#define UNIX_SEQPACKET

extern struct fuse_operations stub_operations;
extern struct fuse_operations proxy_operations;
extern struct fuse_operations golem_operations;

extern int create_socket_interface(struct context_data_s *ctx, const char *socket_path);
extern int start_socket_thread(struct context_data_s *ctx);

struct context_data_s fs_context = {
	.proxy_dir		= NULL,
	.mode			= FUSE_STUB_MODE,
	.operations		= {
		[FUSE_PROXY_MODE]	= &proxy_operations,
		[FUSE_STUB_MODE]	= &stub_operations,
		[FUSE_GOLEM_MODE]	= &golem_operations,
	},
	.root_lock		= PTHREAD_MUTEX_INITIALIZER,
	.packet_socket		= -1,
};

struct context_data_s *get_context(void)
{
	return &fs_context;
}

const struct fuse_operations *get_operations(int mode)
{
	const struct context_data_s *ctx = get_context();
	const struct fuse_operations *ops;

	switch (mode) {
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
			pr_crit("%s: unsupported mode: %d\n", __func__, mode);
			ops = ctx->operations[FUSE_STUB_MODE];
			break;
	}
	return ops;
}

int ctx_mode(void)
{
	return get_context()->mode;
}

int wait_mode_change(int current_mode)
{
	int err;

	err = syscall(SYS_futex, &get_context()->mode, FUTEX_WAIT,
		      current_mode, NULL, NULL, 0);
	if (err)
		return err;
	return -ERESTARTSYS;
}

static int wake_mode_waiters(void)
{
	struct context_data_s *ctx = get_context();

	return syscall(SYS_futex, &ctx->mode, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
}

int set_work_mode(struct context_data_s *ctx, int mode)
{
	pr_info("%s: changing work mode from %d to %d\n", __func__, ctx->mode, mode);
	if (mode == ctx->mode) {
		pr_info("%s: the mode is already %d\n", __func__, ctx->mode);
		return 0;
	}

	switch (mode) {
		case FUSE_STUB_MODE:
		case FUSE_PROXY_MODE:
			/* TODO: hold underlying fs to make sure, that it won't
			 * be removed from underneath of us ? */
		case FUSE_GOLEM_MODE:
			break;
		default:
			pr_err("%s: unsupported mode: %d\n", mode);
			return -EINVAL;
	}

	ctx->mode = mode;
	wake_mode_waiters();
	return 0;

}

static int setup_context(struct context_data_s *ctx, const char *proxy_dir,
			 int mode)
{
	int err = -ENOMEM;

	ctx->proxy_dir = strdup(proxy_dir);
	if (!ctx) {
		pr_err("%s: failed to duplicate string\n", __func__);
		return -ENOMEM;
	}

	ctx->root.name = strdup("/");
	if (!ctx->root.name) {
		pr_err("%s: failed to duplicate string\n", __func__);
		return -ENOMEM;
	}

	err = set_work_mode(ctx, mode);
	if (err) {
		pr_err("Set work mode %d failed\n", mode);
		return err;
	}

	if (pthread_mutex_init(&ctx->root_lock, NULL)) {
		pr_perror("%s: failed to init mode switch", __func__);
		return -errno;
	}

	INIT_LIST_HEAD(&ctx->root.children);
	INIT_LIST_HEAD(&ctx->root.siblings);

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
	pr_debug("%s: proxy_dir   : %s\n", __func__, proxy_dir);
	pr_debug("%s: mode        : %d\n", __func__, mode);
	pr_debug("%s: log         : %s\n", __func__, log_file);
	pr_debug("%s: socket path : %s\n", __func__, socket_path);
	pr_debug("%s: verbosity   : +%d\n", __func__, verbosity);

	err = setup_context(ctx, proxy_dir, mode);
	if (err) {
		pr_crit("Failed to setup context: %d\n", err);
		return err;
	}

	err = create_socket_interface(ctx, socket_path);
	if (err) {
		pr_err("failed to create socket interface: %d\n", err);
		return err;
	}

	if(stat(ctx->proxy_dir, &ctx->root.stat) < 0) {
		pr_crit("%s: failed to stat %s\n", __func__, ctx->proxy_dir);
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
