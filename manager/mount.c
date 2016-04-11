#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <fcntl.h>

#include "include/util.h"
#include "include/log.h"
#include "include/socket.h"

#include "spfs/context.h"

#include "context.h"
#include "interface.h"
#include "mount.h"

static int send_mode(const char *socket_path, spfs_mode_t mode, const char *path_to_send)
{
	size_t len;
	struct external_cmd *package;
	int err;

	pr_debug("changind mode to %d (path: %s)\n", mode, path_to_send ? : "none");
	len = mode_packet_size(path_to_send);

	package = malloc(len);
	if (!package) {
		pr_err("failed to allocate package\n");
		return -ENOMEM;
	}
	fill_mode_packet(package, mode, path_to_send);

	err = send_packet(socket_path, package, len);

	free(package);
	return err;
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

static int freezer_set_state(const char *freezer_cgroup, const char state[])
{
	int fd;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/freezer.state", freezer_cgroup);
	fd = open(path, O_RDWR);
	if (fd < 0) {
		pr_perror("Unable to open %s", path);
		return -1;
	}

	if (write(fd, state, sizeof(state)) != sizeof(state)) {
		pr_perror("Unable to set %s state to %s", freezer_cgroup, state);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int thaw_cgroup(const char *freezer_cgroup)
{
	return freezer_set_state(freezer_cgroup, "THAWED");
}

static int freeze_cgroup(const char *freezer_cgroup)
{
	return freezer_set_state(freezer_cgroup, "FROZEN");
}


static int replace_mounts(struct spfs_manager_context_s *ctx, const char *source, const char *target, const char *freezer_cgroup)
{
	int pid, status;
	int err, err2;

	if (freezer_cgroup) {
		err2 = freeze_cgroup(freezer_cgroup);
		if (err2) {
			pr_err("failed to freeze cgroup %s\n", freezer_cgroup);
			return err2;
		}
		pr_debug("cgroup %s was freezed\n", freezer_cgroup);
	}

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			err = -errno;
			goto thaw_cgroup;
		case 0:
			if (ctx->ns_pid) {
				if (join_namespaces(ctx->ns_pid, ctx->namespaces))
					_exit(EXIT_FAILURE);
			}

			err = umount2(target, MNT_DETACH);
			if (err) {
				pr_perror("failed to umount %s", target);
				_exit(EXIT_FAILURE);
			}

			pr_debug("mountpoint %s was lazily umounted\n", target);

			err = mount(source, target, NULL, MS_BIND, NULL);
			if (err) {
				pr_perror("failed to bind-mount %s to %s", source, target);
				_exit(EXIT_FAILURE);
			}

			pr_debug("mountpoint %s was bind-mounted to %s\n", source, target);
			_exit(EXIT_SUCCESS);
	}

	err = collect_child(pid, &status, 0);
	if (!err)
		err = status;

thaw_cgroup:
	if (freezer_cgroup) {
		err2 = thaw_cgroup(freezer_cgroup);
		if (err2)
			pr_err("failed to thaw cgroup %s\n", freezer_cgroup);
		else
			pr_debug("cgroup %s was thawed\n", freezer_cgroup);
	}
#if 0
	if (!err) {
		if (umount2(source, MNT_DETACH))
			pr_perror("failed to umount %s", source);
		pr_debug("mountpoint %s was lazily umounted\n", source);
	}
#endif
	return err ? err : err2;
}

static int umount_target(struct spfs_manager_context_s *ctx, const char *mnt)
{
	int pid, err, status;

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			return -errno;
		case 0:
			if (ctx->ns_pid) {
				if (join_namespaces(ctx->ns_pid, ctx->namespaces))
					_exit(EXIT_FAILURE);
			}

//			if (secure_chroot(ctx->spfs_root))
//				_exit(EXIT_FAILURE);

			if (umount2(mnt, MNT_DETACH)) {
				pr_perror("failed to umount %s");
				_exit(EXIT_FAILURE);
			}
			_exit(EXIT_SUCCESS);
	}

	err = collect_child(pid, &status, 0);

	return err ? err : status;
}

static int mount_target(int sock, struct spfs_manager_context_s *ctx,
			const char *source, const char *mnt, const char *fstype,
			long mountflags, const char *options)
{
	int pid, err, status;

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			return -errno;
		case 0:
			if (ctx->ns_pid) {
				if (join_namespaces(ctx->ns_pid, ctx->namespaces))
					_exit(EXIT_FAILURE);
			}

			if (secure_chroot(ctx->spfs_root))
				_exit(EXIT_FAILURE);

			if (send_status(sock, 0))
				_exit(EXIT_FAILURE);

			_exit(mount_loop(ctx, source, mnt, fstype, mountflags, options));
	}

	err = collect_child(pid, &status, 0);

	return err ? err : status;
}

int mount_fs(int sock, struct spfs_manager_context_s *ctx, void *package, size_t psize)
{
	struct mount_fs_package_s *p = package;
	char *mnt;
	int err = -1;
	char *source = NULL, *fstype = NULL, *options = NULL;
	int mode = SPFS_PROXY_MODE;

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

	if (create_dir("%s%s", ctx->spfs_root, mnt)) {
		pr_perror("failed to create mountpoint %s", mnt);
		goto free_mnt;
	}

	err = mount_target(sock, ctx, source, mnt, fstype, p->mountflags, options);
	if (err)
		goto free_mnt;

	pr_debug("successfully mounted %s to %s\n", fstype, mnt);

	err = send_mode(ctx->spfs_socket, mode, mnt);
	if (err) {
		pr_err("failed to switch spfs to proxy mode to %s: %d\n", mnt,
				err);
		goto free_mnt;
	}

	pr_debug("spfs mode was changed to %d (path: %s)\n", mode, mnt);

	err = replace_mounts(ctx, mnt, ctx->mountpoint, ctx->freeze_cgroup);
	if (err) {
		pr_err("failed to repalce mounts\n");
		goto free_mnt;
	}

	pr_debug("mountpoint %s replaced %s\n", mnt, ctx->mountpoint);

	err = send_mode(ctx->spfs_socket, mode, ctx->mountpoint);
	if (err) {
		pr_err("failed to switch spfs to proxy mode to %s: %d\n", mnt,
				err);
		goto free_mnt;
	}

	pr_debug("spfs mode was changed to %d (path: %s)\n", mode, ctx->mountpoint);

	(void) umount_target(ctx, mnt);

free_mnt:
	free(mnt);
free_mount_data:
	free(source);
	free(fstype);
	free(options);
	return err;
}
