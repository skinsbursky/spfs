#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>

#include "util.h"
#include "context.h"
#include "log.h"
#include "interface.h"

#define UNIX_SEQPACKET

static struct dentry_info_s *add_dentry_info(struct dentry_info_s *parent,
					     const char *dentry)
{
	struct dentry_info_s *child;

	if ((parent->stat.st_mode & S_IFMT) != S_IFDIR) {
		pr_err("%s: can't add dentry \"%s\" to parent \"%s\": not a directory\n", __func__, dentry, parent->name);
		return NULL;
	}

	child = malloc(sizeof(*child));
	if (!child)
		return NULL;
	child->name = strdup(dentry);
	if (!child->name) {
		free(child);
		return NULL;
	}

	INIT_LIST_HEAD(&child->children);
	INIT_LIST_HEAD(&child->siblings);
	list_add_tail(&child->siblings, &parent->children);
	child->parent = parent;

	memcpy(&child->stat, &parent->stat, sizeof(child->stat));

	pr_info("%s: added dentry \"%s\" to parent \"%s\"\n", __func__, child->name, parent->name);
	return child;
}

static struct dentry_info_s *find_child_info(struct dentry_info_s *parent,
					     const char *dentry)
{
	struct dentry_info_s *child;

	list_for_each_entry(child, &parent->children, siblings) {
		if (!strcmp(child->name, dentry))
			return child;
	}
	return NULL;
}

static int context_add_path(struct context_data_s *ctx, const struct dentry_package_s *dp)
{
	char *path, *dentry;
	struct dentry_info_s *cur_info = &ctx->root, *child_info = NULL;
	int err = -ENOMEM;

	path = strdup(dp->path);
	if (!path) {
		pr_err("Failed to duplicate path\n");
		return -ENOMEM;
	}

	while ((dentry = strsep(&path, "/")) != NULL) {
		pr_debug("%s: traversing dentry: \"%s\"\n", __func__, dentry);

		if (strlen(dentry) == 0) {
			pr_debug("%s: dentry is empty, skipping\n", __func__);
			continue;
		}
		if (!strcmp(dentry, ".")) {
			pr_debug("%s: dentry is \".\", skipping\n", __func__);
			continue;
		}
		if (!strcmp(dentry, "..")) {
			pr_debug("%s: dentry is \"..\", rollback to parent\n", __func__);
			cur_info = cur_info->parent;
			continue;
		}

		child_info = find_child_info(cur_info, dentry);
		if (!child_info)
			child_info = add_dentry_info(cur_info, dentry);
		if (!child_info)
			goto err;
		cur_info = child_info;
	}
	if (!child_info) {
		err = -EINVAL;
		pr_err("%s: path is empty: \"%s\"\n", __func__, dp->path);
		goto err;
	}

	if (list_empty(&child_info->children))
		memcpy(&child_info->stat, &dp->stat, sizeof(child_info->stat));
	pr_info("%s: \"%s\" size: %ld\n", __func__, dp->path, child_info->stat.st_size);
	pr_info("%s: \"%s\" mode: 0%o\n", __func__, dp->path, child_info->stat.st_mode);
	err = 0;
err:
	free(path);
	return err;
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
			return change_work_mode(ctx, mp->mode, mp->path);
		case FUSE_CMD_INSTALL_PATH:
			dp = (struct dentry_package_s *)order->ctx;

			pr_debug("%s: dp->stat.st_dev   : %ld\n", __func__, dp->stat.st_dev);
			pr_debug("%s: dp->stat.st_ino   : %ld\n", __func__, dp->stat.st_ino);
			pr_debug("%s: dp->stat.st_mode  : 0%o\n", __func__, dp->stat.st_mode);
			pr_debug("%s: dp->stat.st_nlink : %ld\n", __func__, dp->stat.st_nlink);
			pr_debug("%s: dp->stat.st_uid   : %d\n", __func__, dp->stat.st_uid);
			pr_debug("%s: dp->stat.st_gid   : %d\n", __func__, dp->stat.st_gid);
			pr_debug("%s: dp->stat.st_size  : %ld\n", __func__, dp->stat.st_size);
			pr_debug("%s: dp->stat.st_blocks: %ld\n", __func__, dp->stat.st_blocks);
			pr_debug("%s: dp->path          : \"%s\"\n", __func__, dp->path);

			err = context_add_path(ctx, dp);
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
			int err;

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

			err = execute_cmd(ctx, page);

			bytes = send(sock, &err, sizeof(&err), MSG_NOSIGNAL | MSG_DONTWAIT | MSG_EOR);
			if (bytes < 0) {
				pr_perror("%s: write failed", __func__, bytes);
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
