#include "spfs_config.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
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
	const char *work_dir = ctx->work_dir;
	char *mountpoint = ctx->mountpoint;
	int pid, status;
	const char *spfs = FS_NAME;
	char *proxy_dir;
	char *log_path;

	log_path = xsprintf("%s/spfs.log", work_dir);
	if (!log_path)
		return -ENOMEM;

	ctx->spfs_socket = xsprintf("%s/spfs.sock", work_dir);
	if (!ctx->spfs_socket)
		return -ENOMEM;

	proxy_dir = xsprintf("%s/mnt", work_dir);
	if (!proxy_dir)
		return -ENOMEM;

	if (mkdir(proxy_dir, 0755) && (errno != EEXIST)) {
		pr_perror("failed to create %s", proxy_dir);
		return -errno;
	}

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			return -errno;
		case 0:
			execvp_print(spfs, (char *[]){ "spfs", "-vvvv",
				"--mode", ctx->start_mode,
				"--proxy_dir", ctx->proxy_dir,
				"--root", ctx->root,
				"--socket_path", ctx->spfs_socket,
				"--log", log_path,
				mountpoint, NULL });

			_exit(EXIT_FAILURE);
	}

	free(log_path);
	free(proxy_dir);

	pid = waitpid(pid, &status, 0);
	if (pid < 0) {
		pr_perror("Wait for %d failed", pid);
		return -errno;
	}

	if (WIFSIGNALED(status)) {
		pr_err("spfs(%d) was killed by %d\n", pid, WTERMSIG(status));
		return -ECANCELED;
	}

	if (WEXITSTATUS(status)) {
		pr_err("spfs(%d) exited with error %d\n", pid, WEXITSTATUS(status));
		return WEXITSTATUS(status);
	}

	pr_info("%s: spfs on %s started successfully\n", __func__, mountpoint);
	return WEXITSTATUS(status);
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
