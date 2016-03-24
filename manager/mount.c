#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>

#include "include/util.h"
#include "include/log.h"
#include "include/socket.h"

#include "spfs/context.h"

#include "context.h"
#include "interface.h"
#include "mount.h"

static int send_mode(const char *socket_path, int mode, const char *path_to_send)
{
	size_t len;
	struct external_cmd *package;

	pr_debug("changind mode to %d (path: %s)\n", mode, path_to_send ? : "none");
	len = mode_packet_size(path_to_send);

	package = malloc(len);
	if (!package) {
		pr_err("failed to allocate package\n");
		return -ENOMEM;
	}
	fill_mode_packet(package, mode, path_to_send);

	return send_packet(socket_path, package, len);
}

static int parse_mount_data(struct mount_fs_package_s *p,
			    char **source, char **fstype, char **options)
{
	char *token, *str;
	int err = -ENOMEM, nr = 0;
	char *tokens[] = {
		NULL, NULL, NULL
	}, **ptr;

	pr_debug("mountdata: %s\n", p->mountdata);

	str = strdup(p->mountdata);
	if (!str) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	while ((token = strsep(&str, ";")) != NULL) {
		if (nr >= sizeof(tokens)/sizeof(char *)) {
			pr_err("invalid token: %s (>3)\n", token);
			goto free_tokens;
		}
		pr_debug("token: %s\n", token);
		tokens[nr] = strdup(token);
		if (!tokens[nr]) {
			pr_err("failed to duplicate token\n");
			goto free_tokens;
		}
		nr++;
	}

	*source = tokens[0];
	*fstype = tokens[1];
	*options = tokens[2];

	err = -EINVAL;

	if (!*source) {
		pr_err("source wasn't provided\n");
		goto free_tokens;
	}

	if (!*fstype) {
		pr_err("file system type wasn't provided\n");
		goto free_tokens;
	}

	if (!*options) {
		pr_err("mount options weren't provided\n");
		goto free_tokens;
	}

	err = 0;

free_string:
	free(str);
	return err;

free_tokens:
	ptr = &tokens[0];
	while (*ptr)
		free(*ptr++);
	goto free_string;
}

int mount_fs(struct spfs_manager_context_s *ctx, void *package, size_t psize)
{
	struct mount_fs_package_s *p = package;
	char *mnt;
	int err = -1;
	char *source = NULL, *fstype = NULL, *options = NULL;

	if (parse_mount_data(p, &source, &fstype, &options)) {
		pr_err("failed to parse mount data\n");
		return -EINVAL;
	}

	if (strlen(source) == 0) {
		source = xsprintf("%s", ctx->progname);
		if (!source)
			goto free_mount_data;
	}

	mnt = xsprintf("%s/%s", ctx->work_dir, fstype);
	if (!mnt) {
		pr_err("failed to allocate\n");
		goto free_mount_data;
	}

	if (mkdir(mnt, 0600)) {
		pr_perror("failed to create mountpoint %s", mnt);
		goto free_mnt;
	}

	err = mount(source, mnt, fstype, p->mountflags, options);
	if (err) {
		pr_perror("failed to mount %s", fstype);
		goto rmdir_mnt;
	}

	err = send_mode(ctx->spfs_socket, SPFS_PROXY_MODE, mnt);
	if (err) {
		pr_err("failed to switch spfs to ppoxy mode to %s: %d\n", mnt,
				err);
		goto umount;
	}

	/* TODO: replace mount points */

free_mnt:
	free(mnt);
free_mount_data:
	free(source);
	free(fstype);
	free(options);
	return err;
umount:
	if (umount(mnt))
		pr_perror("failed to umount %s\n", mnt);
rmdir_mnt:
	if (rmdir(mnt))
		pr_perror("failed to remove %s\n", mnt);
	goto free_mnt;
}
