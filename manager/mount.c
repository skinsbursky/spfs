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

	printf("changind mode to %d (path: %s)\n", mode, path_to_send ? : "none");
	len = mode_packet_size(path_to_send);

	package = malloc(len);
	if (!package) {
		printf("failed to allocate package\n");
		return -ENOMEM;
	}
	fill_mode_packet(package, mode, path_to_send);

	return send_packet(socket_path, package, len);
}

int mount_fs(struct spfs_manager_context_s *ctx, void *package, size_t psize)
{
	struct mount_fs_package_s *p = package;
	char *mnt;
	int err = -1;

	mnt = xsprintf("%s/%s", ctx->work_dir, p->filesystemtype);
	if (!mnt) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	if (mkdir(mnt, 0600)) {
		pr_perror("failed to create mountpoint %s", mnt);
		goto free_mnt;
	}

	err = mount(ctx->progname, mnt, p->filesystemtype, p->mountflags, p->data);
	if (err) {
		pr_perror("failed to mount %s", p->filesystemtype);
		goto free_mnt;
	}

	err = send_mode(ctx->spfs_socket, SPFS_PROXY_MODE, mnt);
	if (err) {
		pr_err("failed to switch spfs to rpoxy mode to %s\n", mnt);
		goto umount;
	}

	/* TODO: replace mount points */

free_mnt:
	free(mnt);
	return err;
umount:
	if (umount(mnt))
		pr_perror("failed to umount %s\n", mnt);
	goto free_mnt;
}
