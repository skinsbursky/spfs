#include "spfs_config.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sched.h>
#include <limits.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>

#include "include/util.h"
#include "include/log.h"
#include "include/socket.h"

#include "spfs/context.h"

#include "context.h"
#include "interface.h"

static int mount_spfs(struct spfs_manager_context_s *ctx)
{
	const char *work_dir = ctx->work_dir, *spfs = FS_NAME;
	char *proxy_dir, *log_path;
	int pid, status;

	log_path = xsprintf("%s/spfs.log", work_dir);
	if (!log_path)
		return -ENOMEM;

	ctx->spfs_socket = xsprintf("%s/spfs.sock", work_dir);
	if (!ctx->spfs_socket)
		return -ENOMEM;

	proxy_dir = xsprintf("%s/mnt", ctx->spfs_dir);
	if (!proxy_dir)
		return -ENOMEM;

	/* TODO WTF? Mode can be Stub */
	if (create_dir("%s%s", ctx->root ? ctx->root : "", proxy_dir))
		return -EINVAL;

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			return -errno;
		case 0:
			if (join_namespaces(ctx->ns_pid, ctx->namespaces))
				_exit(EXIT_FAILURE);

			execvp_print(spfs, (char *[]){ "spfs", "-vvvv",
				"--mode", ctx->start_mode,
				"--proxy-dir", ctx->proxy_dir,
				"--root", ctx->root,
				"--socket-path", ctx->spfs_socket,
				"--log", log_path,
				ctx->mountpoint, NULL });

			_exit(EXIT_FAILURE);
	}

	free(log_path);
	free(proxy_dir);

	if (collect_child(pid, &status))
		return -1;

	if (!status)
		pr_info("%s: spfs on %s started successfully\n", __func__,
				ctx->mountpoint);

	return status;
}

int main(int argc, char *argv[])
{
	struct spfs_manager_context_s *ctx;

	ctx = create_context(argc, argv);
	if (!ctx)
		return -1;

	if (mount_spfs(ctx))
		return -EINVAL;

	if (ctx->daemonize) {
		if (daemon(0, 0)) {
			pr_perror("failed to daemonize");
			return -errno;
		}
	}

	return reliable_socket_loop(ctx->sock, ctx, true, spfs_manager_packet_handler);
}
