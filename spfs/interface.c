#include "spfs_config.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>

#include "include/util.h"
#include "context.h"
#include "include/log.h"
#include "interface.h"

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

static int context_add_path(struct spfs_context_s *ctx, const struct dentry_package_s *dp)
{
	char *path, *dentry;
	struct dentry_info_s *cur_info = &ctx->root, *child_info = NULL;
	int err = -ENOMEM;

	path = strdup(dp->path);
	if (!path) {
		pr_err("failed to duplicate path\n");
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

int spfs_execute_cmd(void *data, void *package, size_t psize)
{
	struct spfs_context_s *ctx = data;
	struct external_cmd *order;
	struct dentry_package_s *dp;
	struct cmd_package_s *mp;
	int err;

	order = (struct external_cmd *)package;
	pr_debug("%s: cmd: %d\n", __func__, order->cmd);
	switch (order->cmd) {
		case SPFS_CMD_SET_MODE:
			mp = (struct cmd_package_s *)order->ctx;
			return change_work_mode(ctx, mp->mode, mp->path);
		case SPFS_CMD_INSTALL_PATH:
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
