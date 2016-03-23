#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>

#include "include/util.h"
#include "include/log.h"

#include "context.h"
#include "interface.h"
#include "mount.h"

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

	/* TODO: signal spfs to switch to this mountpoint */

free_mnt:
	free(mnt);
	return err;
}
