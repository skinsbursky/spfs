#include "spfs_config.h"

#include <unistd.h>
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <linux/futex.h>
#include <syscall.h>

#include "include/util.h"
#include "context.h"
#include "include/log.h"
#include "include/socket.h"
#include "interface.h"

#define UNIX_SEQPACKET

extern struct fuse_operations stub_operations;
extern struct fuse_operations proxy_operations;

struct spfs_context_s fs_context = {
	.operations		= {
		[SPFS_PROXY_MODE]	= &proxy_operations,
		[SPFS_STUB_MODE]	= &stub_operations,
	},
	.root_lock		= PTHREAD_MUTEX_INITIALIZER,
	.wm_lock		= PTHREAD_MUTEX_INITIALIZER,
	.packet_socket		= -1,
};

const char *work_modes[] = {
	[SPFS_PROXY_MODE]	= "Proxy",
	[SPFS_STUB_MODE]	= "Stub",
};

struct spfs_context_s *get_context(void)
{
	return &fs_context;
}

const struct fuse_operations *get_operations(struct work_mode_s *wm)
{
	const struct spfs_context_s *ctx = get_context();
	const struct fuse_operations *ops;

	switch (wm->mode) {
		case SPFS_PROXY_MODE:
		case SPFS_STUB_MODE:
			ops = ctx->operations[wm->mode];
			break;
		default:
			pr_crit("%s: unsupported mode: %d\n", __func__, wm->mode);
			ops = ctx->operations[SPFS_STUB_MODE];
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

static int wake_mode_waiters(struct work_mode_s *wm)
{
	return syscall(SYS_futex, &wm->mode, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
}

static int create_work_mode(spfs_mode_t mode, const char *path, struct work_mode_s **wm)
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
		/* TODO: don't hold the reference, because on case of chroot
		 * ("root" option) this path won't be accessible.
		 * This have to be fixed later. Maybe it's not required at all.
		 * Say, one first starts spfs and only then mounts actual proxy.
		 */
#if 0
		/* Take a reference to underlying fs to make sure, that
		 * it won't be removed from underneath of us. */
		new->proxy_root_fd = open(new->proxy_dir, O_PATH);
		if (new->proxy_root_fd == -1) {
			pr_perror("failed to open %s", new->proxy_dir);
			err = -errno;
			goto free_proxy_dir;
		}
#endif
	}
	*wm = new;
	return 0;
#if 0
free_proxy_dir:
	free(new->proxy_dir);
#endif
free_new:
	free(new);
	return err;
}

int copy_work_mode(struct work_mode_s **wm)
{
	struct spfs_context_s *ctx = get_context();
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

int stale_work_mode(spfs_mode_t mode, const char *proxy_dir)
{
	struct spfs_context_s *ctx = get_context();

	if (mode != ctx->wm->mode)
		return 1;

	return !!strcmp(proxy_dir, ctx->wm->proxy_dir);
}

int set_work_mode(struct spfs_context_s *ctx, spfs_mode_t mode, const char *path)
{
	struct work_mode_s *cur_wm = get_context()->wm;
	struct work_mode_s *new_wm = NULL;
	int err;

	switch (mode) {
		case SPFS_PROXY_MODE:
		case SPFS_STUB_MODE:
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

			wake_mode_waiters(cur_wm);

			destroy_work_mode(cur_wm);
			break;
		default:
			pr_err("%s: unsupported mode: %d\n", mode);
			return -EINVAL;
	}
	return 0;
}

int change_work_mode(struct spfs_context_s *ctx, spfs_mode_t mode, const char *path)
{
	pr_info("%s: changing work mode from %d to %d (path: %s)\n", __func__, ctx->wm->mode, mode, path);
	if (!stale_work_mode(mode, path)) {
		pr_info("%s: the mode is already %d\n", __func__, ctx->wm->mode);
		return 0;
	}
	return set_work_mode(ctx, mode, path);
}


static int setup_context(struct spfs_context_s *ctx, const char *proxy_dir,
			 spfs_mode_t mode, bool single_user)
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
	ctx->single_user = single_user;

	return 0;
}

int context_store_mnt_stat(const char *mountpoint)
{
	struct spfs_context_s *ctx = get_context();
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

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>

static void *sock_routine(void *ptr)
{
        struct spfs_context_s *ctx = ptr;

	(void) reliable_socket_loop(ctx->packet_socket, ctx, false, spfs_execute_cmd);
	return NULL;
}

int context_init(const char *proxy_dir, spfs_mode_t mode, const char *log_file,
		 const char *socket_path, int verbosity, const char *mountpoint,
		 bool single_user)
{
	struct spfs_context_s *ctx = get_context();
	int err;

	pr_debug("fuse: opening log %s\n", log_file);

	err = setup_log(log_file, verbosity);
	if (err) {
		pr_crit("failed to open log: %d\n", err);
		return err;
	}

	err = setup_context(ctx, proxy_dir, mode, single_user);
	if (err) {
		pr_crit("failed to setup context: %d\n", err);
		return err;
	}

	if (context_store_mnt_stat(mountpoint))
		return -1;

	ctx->packet_socket = seqpacket_sock(socket_path, true, true,
					    &ctx->sock_addr);
	if (ctx->packet_socket < 0) {
		pr_err("failed to create socket interface\n");
		return ctx->packet_socket;
	}

	err = pthread_create(&ctx->sock_pthread, NULL, sock_routine, ctx);
	if (err) {
		pr_perror("%s: failed to create socket pthread", __func__);
		return -errno;
	}

	pr_debug("%s: created pthread with ID %ld\n", __func__, ctx->sock_pthread);
	return 0;
}

void context_fini(void)
{
	struct spfs_context_s *ctx = get_context();
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
