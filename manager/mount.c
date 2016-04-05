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

static int do_mount(const char *source, const char *mnt,
			const char *fstype, unsigned long mountflags,
			const char *options)
{
	int err;

	err = mount(source, mnt, fstype, mountflags, options);
	if (!err)
		return 0;

	switch (errno) {
		case EPROTONOSUPPORT:
		case EPERM:
			pr_warn("failed to mount %s to %s: %s\n", fstype, mnt,
					strerror(errno));
			return -EAGAIN;
	}
	return -errno;
}

static int mount_loop(struct spfs_manager_context_s *ctx,
			const char *source, const char *mnt,
			const char *fstype, unsigned long mountflags,
			const char *options)
{
	int err = 0;
	int timeout = 1;

	while (1) {
		err = do_mount(source, mnt, fstype, mountflags, options);
		if (err != -EAGAIN)
			break;

		pr_warn("retrying in %d seconds\n", timeout);
		sleep(timeout);

		if (timeout < 32)
			timeout <<= 1;
	}

	if (err) {
		pr_perror("failed to mount %s to %s: %s", fstype, mnt,
					strerror(errno));
		goto rmdir_mnt;
	}

	pr_info("Successfully mounted %s to %s\n", fstype, mnt);

	return 0;

rmdir_mnt:
	if (rmdir(mnt))
		pr_perror("failed to remove %s", mnt);
	return err;

}

int mount_fs(struct spfs_manager_context_s *ctx, void *package, size_t psize)
{
	struct mount_fs_package_s *p = package;
	char *mnt;
	int err = -1, pid, status;
	char *source = NULL, *fstype = NULL, *options = NULL;

	if (parse_mount_data(p, &source, &fstype, &options)) {
		pr_err("failed to parse mount data\n");
		return -EINVAL;
	}

	if (strlen(source) == 0) {
		source = xstrcat(source, "%s", ctx->progname);
		if (!source)
			goto free_mount_data;
	}

	mnt = xsprintf("%s/%s", ctx->spfs_dir, fstype);
	if (!mnt) {
		pr_err("failed to allocate\n");
		goto free_mount_data;
	}

	if (create_dir(mnt)) {
		pr_perror("failed to create mountpoint %s", mnt);
		goto free_mnt;
	}

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			err = -errno;
			goto free_mnt;
		case 0:
			if (ctx->ns_pid) {
				if (join_namespaces(ctx->ns_pid, ctx->namespaces))
					_exit(EXIT_FAILURE);
			}

			if (ctx->root && chroot(ctx->root)) {
				pr_perror("failed to chroot to %s", ctx->root);
				_exit(EXIT_FAILURE);
			}

			_exit(mount_loop(ctx, source, mnt, fstype, p->mountflags, options));
	}

	err = collect_child(pid, &status);
	if (!err)
		err = status;

	if (!err) {
		err = send_mode(ctx->socket_path, SPFS_PROXY_MODE, mnt);
		if (err)
			pr_err("failed to switch spfs to proxy mode to %s: %d\n", mnt,
					err);
	}

	pr_debug("spfs mode was changed to %d (path: %s)\n", SPFS_PROXY_MODE, mnt);

free_mnt:
	free(mnt);
free_mount_data:
	free(source);
	free(fstype);
	free(options);
	return err;
}
