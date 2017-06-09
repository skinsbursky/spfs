#include "spfs_config.h"

#include <unistd.h>
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "include/util.h"
#include "include/log.h"
#include "include/socket.h"
#include "include/futex.h"
#include "include/namespaces.h"

#include "interface.h"
#include "context.h"

#define UNIX_SEQPACKET

extern struct fuse_operations stub_operations;
extern struct fuse_operations proxy_operations;

struct spfs_context_s fs_context = {
	.operations		= {
		[SPFS_PROXY_MODE]	= &proxy_operations,
		[SPFS_STUB_MODE]	= &stub_operations,
	},
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

	err = futex_wait(&get_context()->wm->mode, current_mode, NULL);
	if (err)
		return err;
	return -ERESTARTSYS;
}

static int wake_mode_waiters(struct work_mode_s *wm)
{
	return futex_wake(&wm->mode);
}

static int open_proxy_directory(const char *path, int ns_pid)
{
	int err, mnt_ns_fd, dfd;
        struct spfs_context_s *ctx = get_context();

	mnt_ns_fd = open_ns(ns_pid, NS_MNT);
	if (mnt_ns_fd < 0)
		return mnt_ns_fd;

	err = set_ns(mnt_ns_fd);
	if (err)
		goto close_ns_fd;

	dfd = open(path, O_PATH);
	if (dfd == -1) {
		pr_perror("failed to open %s", path);
		err = -errno;
		goto close_ns_fd;
	}

	err = set_ns(ctx->mnt_ns_fd);
	if (err)
		goto close_fd;

close_ns_fd:
        close(mnt_ns_fd);
	return err ? err : dfd;

close_fd:
	close(dfd);
	goto close_ns_fd;
}

static int create_work_mode(spfs_mode_t mode,
			    const char *path, int mnt_ns_pid,
			    struct work_mode_s **wm)
{
	struct work_mode_s *new;
	int err;

	new = malloc(sizeof(*new));
	if (!new) {
		pr_err("%s: failed to allocate work mode structure\n", __func__);
		return -ENOMEM;
	}

	new->mode = mode;
	new->cnt = 1;
	new->proxy_dir_fd = -1;
	new->proxy_dir = NULL;

	if (mode == SPFS_PROXY_MODE) {
		if (!strlen(path)) {
			pr_err("%s: proxy directory is empty\n", __func__);
			err = -EINVAL;
			goto free_new;
		}

		new->proxy_dir = strdup(path);
		if (!new->proxy_dir) {
			pr_err("%s: failed to allocate proxy_dir for work mode structure\n", __func__);
			err = -ENOMEM;
			goto free_new;
		}

		/* Take a reference to proxy directory to make sure, that
		 * it won't be removed from underneath of us. */
		new->proxy_dir_fd = open_proxy_directory(new->proxy_dir, mnt_ns_pid);
		if (new->proxy_dir_fd < 0) {
			err = new->proxy_dir_fd;
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

static void destroy_work_mode(struct work_mode_s *wm)
{
	if (wm->proxy_dir_fd != -1)
		close(wm->proxy_dir_fd);
	if (wm->proxy_dir)
		free(wm->proxy_dir);
	free(wm);
}

/* Well... Get and put methods below are worng in generic case.
 * They work properly, because:
 * 1) Current work mode is being hold by context. And in *get* method we
 * protect agains its change.
 * 2) Any arch word operation is atomic on x86 arch.
 * These two assumtions are enough to make this work properly on x86{_64}
 * architecture.
 * For others we either need to protec these operations by lock, or introduced
 * atomic operations.
 */

void put_work_mode(struct work_mode_s *wm)
{
	if (!wm)
		return;

	if (--wm->cnt)
		return;

	destroy_work_mode(wm);
}

struct work_mode_s *get_work_mode(void)
{
	struct spfs_context_s *ctx = get_context();
	struct work_mode_s *wm;
	int err;

	/* Protect against work mode change */
	err = pthread_mutex_lock(&ctx->wm_lock);
	if (err) {
		pr_err("%s: failed to lock wm_lock: %d\n", __func__, err);
		return NULL;
	}

	wm = ctx->wm;
	wm->cnt++;

        pthread_mutex_unlock(&ctx->wm_lock);
	return wm;
}

static bool stale_work_mode(spfs_mode_t mode, const char *proxy_dir)
{
	struct spfs_context_s *ctx = get_context();

	if (mode == SPFS_PROXY_MODE)
		return true;

	return mode != ctx->wm->mode;
}

int set_work_mode(struct spfs_context_s *ctx, spfs_mode_t mode,
		  const char *path, int mnt_ns_pid)
{
	struct work_mode_s *cur_wm = get_context()->wm;
	struct work_mode_s *new_wm = NULL;
	int err;

	switch (mode) {
		case SPFS_PROXY_MODE:
		case SPFS_STUB_MODE:
			err = create_work_mode(mode, path, mnt_ns_pid, &new_wm);
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

			if (cur_wm) {
				wake_mode_waiters(cur_wm);
				put_work_mode(cur_wm);
			}
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
	return set_work_mode(ctx, mode, path, 0);
}


static int setup_context(struct spfs_context_s *ctx,
			 const char *proxy_dir, int proxy_mnt_ns_pid,
			 spfs_mode_t mode, bool single_user)
{
	int err;

	err = set_work_mode(ctx, mode, proxy_dir, proxy_mnt_ns_pid);
	if (err) {
		pr_err("Set work mode %d failed\n", mode);
		return err;
	}

	ctx->single_user = single_user;

	return 0;
}

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>

static void *sock_routine(void *ptr)
{
        struct spfs_context_s *ctx = ptr;

	pr_info("%s: socket loop started\n", __func__);

	while(1) {
		int sock, err;;

		sock = accept(ctx->packet_socket, NULL, NULL);
		if (sock < 0) {
			pr_perror("%s: accept failed", __func__);
			break;
		}

		pr_debug("%s: accepted new socket\n", __func__);

		do {
			err = reliable_conn_handler(sock, ctx, spfs_execute_cmd);
		} while (ctx->single_user && (err == 0));

		pr_debug("%s: closed interface socket\n", __func__);

		close(sock);
	}

	return NULL;
}

int start_socket_thread(void)
{
	struct spfs_context_s *ctx = get_context();
	int err;

	err = pthread_create(&ctx->sock_pthread, NULL, sock_routine, ctx);
	if (err) {
		pr_perror("%s: failed to create socket pthread", __func__);
		return -errno;
	}

	pr_debug("%s: created pthread with ID %ld\n", __func__, ctx->sock_pthread);
	return 0;
}

int context_init(const char *proxy_dir, int proxy_mnt_ns_pid,
		 spfs_mode_t mode, const char *log_file,
		 const char *socket_path, int verbosity, bool single_user)
{
	struct spfs_context_s *ctx = get_context();
	int err;

	pr_debug("fuse: opening log %s\n", log_file);

	err = setup_log(log_file, verbosity);
	if (err) {
		pr_crit("failed to open log: %d\n", err);
		return err;
	}

	ctx->mnt_ns_fd = open_ns(getpid(), NS_MNT);
	if (ctx->mnt_ns_fd < 0)
		return ctx->mnt_ns_fd;

	err = setup_context(ctx, proxy_dir, proxy_mnt_ns_pid, mode, single_user);
	if (err) {
		pr_crit("failed to setup context: %d\n", err);
		return err;
	}

	ctx->packet_socket = seqpacket_sock(socket_path, true, true,
					    &ctx->sock_addr);
	if (ctx->packet_socket < 0) {
		pr_err("failed to create socket interface\n");
		return ctx->packet_socket;
	}

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
}
