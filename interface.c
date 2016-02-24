#include "config.h"

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>

#include "util.h"
#include "context.h"
#include "log.h"
#include "interface.h"

#define UNIX_SEQPACKET

static int context_add_one_dentry(struct context_data_s *ctx,
				  struct dentry_info_s *parent,
				  const char *dentry, size_t len,
				  struct stat *stat)
{
	struct dentry_info_s *child;

	list_for_each_entry(child, &parent->children, siblings) {
		if (!strcmp(child->name, dentry)) {
			pr_debug("%s: dentry \"%s\" already exists\n", __func__, child->name);
			return 0;
		}
	}

	child = malloc(sizeof(*child));
	if (!child)
		return -ENOMEM;
	child->name = malloc(len + 1);
	if (!child->name)
		return -ENOMEM;
	memset(child->name, 0, len + 1);

	if (!stat)
		stat = &parent->stat;

	memcpy(&child->stat, stat, sizeof(*stat));
	INIT_LIST_HEAD(&child->children);
	INIT_LIST_HEAD(&child->siblings);
	strncpy(child->name, dentry, len);
	list_add_tail(&child->siblings, &parent->children);

	pr_info("%s: added dentry \"%s\" to parent \"%s\"\n", __func__, child->name, parent->name);
	return 0;
}

static int context_add_dentry(struct context_data_s *ctx, struct dentry_package_s *dp)
{
	char *ptr = dp->path;
	struct dentry_info_s *parent = &ctx->root;
	int ret = -EINVAL;
	const char *dentry = NULL;
	ptr = &ptr[strlen(ptr)];
	while (*--ptr == '/')
		*ptr = '\0';

	ptr = dp->path;
	if (*ptr++ != '/') {
		pr_err("%s: path must begin with '/': \"%s\"\n", __func__, ptr);
		return -EINVAL;
	}

	if (pthread_mutex_lock(&ctx->root_lock)) {
		pr_err("%s: failed to lock root\n", __func__);
		return -EINVAL;
	}

repeat:
	while (1) {
		struct dentry_info_s *child;
		int found = 0;

		dentry = ptr;
		ptr = strchr(ptr, '/');
		if (!ptr)
			break;

		list_for_each_entry(child, &parent->children, siblings) {
			if (!strncmp(child->name, dentry, ptr - dentry)) {
				parent = child;
				ptr++;
				found = 1;
				break;
			}
		}
		if (!found)
			break;
	}

	pr_debug("%s: found parent \"%s\" for path \"%s\" (dentry: \"%s\")\n", __func__, parent->name, dp->path, dentry);

	if (strchr(dentry, '/')) {
		pr_debug("%s: tree is incomplete for path: \"%s\"\n", __func__, dp->path);
		if (context_add_one_dentry(ctx, parent, dentry, ptr - dentry, NULL))
			goto unlock;
		goto repeat;
	}

	if ((parent->stat.st_mode & S_IFMT) != S_IFDIR) {
		pr_err("%s: path \"%s\" is wrong: dentry \"%s\" is not a directory\n", __func__, dp->path, parent->name);
		goto unlock;
	}

	ret = context_add_one_dentry(ctx, parent, dentry, strlen(dentry), &dp->stat);
unlock:
	pthread_mutex_unlock(&ctx->root_lock);
	return ret;
}

static int execute_cmd(struct context_data_s *ctx, void *cmd)
{
	struct external_cmd *order;
	struct dentry_package_s *dp;
	struct cmd_package_s *mp;
	int err;

	order = (struct external_cmd *)cmd;
	pr_debug("%s: cmd: %d\n", __func__, order->cmd);
	switch (order->cmd) {
		case FUSE_CMD_SET_MODE:
			mp = (struct cmd_package_s *)order->ctx;
			return set_work_mode(ctx, mp->mode);
		case FUSE_CMD_INSTALL_PATH:
			dp = (struct dentry_package_s *)order->ctx;

			pr_debug("%s: dp->stat.st_dev   : %ld\n", __func__, dp->stat.st_dev);
			pr_debug("%s: dp->stat.st_ino   : %ld\n", __func__, dp->stat.st_ino);
			pr_debug("%s: dp->stat.st_mode  : %o\n", __func__, dp->stat.st_mode);
			pr_debug("%s: dp->stat.st_nlink : %ld\n", __func__, dp->stat.st_nlink);
			pr_debug("%s: dp->stat.st_uid   : %d\n", __func__, dp->stat.st_uid);
			pr_debug("%s: dp->stat.st_gid   : %d\n", __func__, dp->stat.st_gid);
			pr_debug("%s: dp->stat.st_size  : %ld\n", __func__, dp->stat.st_size);
			pr_debug("%s: dp->stat.st_blocks: %ld\n", __func__, dp->stat.st_blocks);
			pr_debug("%s: dp->path          : \"%s\"\n", __func__, dp->path);

			err = context_add_dentry(ctx, dp);
			if (err < 0)
				pr_err("%s: failed to add path \"%s\"\n", __func__, dp->path);
			return err;
		default:
			pr_err("%s: unknown cmd: %d\n", __func__, order->cmd);
			return -1;
	}
	return 0;
}

static void *sock_routine(void *ptr)
{
	struct context_data_s *ctx = ptr;
	char page[4096];

	pr_info("%s: pthread started\n", __func__);
	while(1) {
		int sock;
#ifdef UNIX_SEQPACKET
		socklen_t len = sizeof(ctx->sock_addr);

		sock = accept(ctx->packet_socket, (struct sockaddr *)&ctx->sock_addr, &len);
		if (sock < 0) {
			pr_perror("%s: accept failed", __func__);
			if (errno == EINTR) {
				pr_debug("%s: exit\n", __func__);
				return NULL;
			}
			continue;
		}
#else
		sock = ctx->packet_socket;
#endif
		pr_debug("%s: accepted new socket\n", __func__);

		while (1) {
			ssize_t bytes;

			bytes = recv(sock, page, sizeof(page), 0);
			if (bytes < 0) {
				pr_perror("%s: read failed", __func__, bytes);
				if (errno == EINTR) {
					pr_debug("%s: exit\n", __func__);
					return NULL;
				}
				break;
			}
			if (bytes == 0) {
				pr_debug("%s: peer was closed\n", __func__);
				break;
			}

			pr_debug("%s: !!!received %ld bytes\n", __func__, bytes);

			execute_cmd(ctx, page);
		}
		close(sock);
	}
	return NULL;
}

int start_socket_thread(struct context_data_s *ctx)
{
	int err;

	err = pthread_create(&ctx->sock_pthread, NULL, sock_routine, ctx);
	if (err) {
		pr_perror("%s: failed to create socket pthread", __func__);
		return -errno;
	}

	pr_debug("%s: created pthread with ID %ld\n", __func__, ctx->sock_pthread);
	return 0;
}

int create_socket_interface(struct context_data_s *ctx, const char *socket_path)
{
	int err, sock;

	pr_debug("fuse: creating socket: %s\n", socket_path);
#ifdef UNIX_SEQPACKET
	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
#else
	sock = socket(AF_UNIX, SOCK_DGRAM, 0);
#endif
	if (sock < 0) {
		pr_perror("%s: failed to create packet socket", __func__);
		return -errno;
	}
	pr_debug("Socket fd: %d\n", sock);

	sock = save_fd(sock);
	if (sock < 0) {
		pr_crit("Failed to save sock fd\n");
		return sock;
	}
	pr_debug("Saved socket fd: %d\n", sock);

	if (!access(socket_path, F_OK) && (unlink(socket_path) < 0)) {
		err = -errno;
		pr_crit("fuse: failed to unlink %s: %d\n", socket_path, -errno);
		return err;
	}

	memset(&ctx->sock_addr, 0, sizeof(struct sockaddr_un));
	ctx->sock_addr.sun_family = AF_UNIX;
	strncpy(ctx->sock_addr.sun_path, socket_path,
			sizeof(ctx->sock_addr.sun_path) - 1);

	err = bind(sock, (struct sockaddr *)&ctx->sock_addr, sizeof(ctx->sock_addr));
	if (err) {
		pr_perror("%s: failed to bind socket to %s", __func__,
				ctx->sock_addr.sun_path);
		goto err;
	}

#ifdef UNIX_SEQPACKET
	if (listen(sock, 20) == -1) {
		pr_perror("%s: failed to listen to socket %s", __func__,
				ctx->sock_addr.sun_path);
		goto err;
	}
#endif

	ctx->packet_socket = sock;

	pr_info("%s: Listening to %s\n", __func__, ctx->sock_addr.sun_path);
	return 0;

err:
	err = -errno;
	close(ctx->packet_socket);
	return err;
}
