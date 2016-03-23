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

#include "context.h"

static int spfs_manager_packet_handler(void *data, void *packet, size_t psize)
{
	pr_err("Interface is not ready yet\n");
	return -ENOENT;
}

static int mount_spfs(const char *work_dir, char *mountpoint)
{
	int pid, status;
	const char *spfs = FS_NAME;
	char *proxy_dir;
	char *socket_path;
	char *log_path;
	/*TODO Add spfs_mode option? */
	/* TODO make mode accepf strings like "stub" or "proxy" ? */
	char *mode = "1";

	log_path = xsprintf("%s/spfs.log", work_dir);
	if (!log_path)
		return -ENOMEM;

	socket_path = xsprintf("%s/spfs.sock", work_dir);
	if (!socket_path)
		return -ENOMEM;

	proxy_dir = xsprintf("%s/mnt", work_dir);
	if (!proxy_dir)
		return -ENOMEM;

	if (mkdir(proxy_dir, 0755) && (errno != EEXIST)) {
		pr_perror("failed to create %s", proxy_dir);
		return -errno;
	}

	pr_debug("%s: 2\n", __func__);

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			return -errno;
		case 0:
			execvp(spfs, (char *[]){ "spfs", "-vvvv",
				/* TODO start with STUB mode and feed with proper directory later */
//				"--proxy_dir", proxy_dir,
				"--mode", mode,
				"--socket_path", socket_path,
				"--log", log_path,
				mountpoint, NULL });

			pr_perror("exec failed");
			_exit(EXIT_FAILURE);
	}

	free(socket_path);
	free(log_path);
	free(proxy_dir);

	pid = waitpid(pid, &status, 0);
	if (pid < 0) {
		pr_perror("Wait for %d failed", pid);
		return -errno;
	}

	if (WIFSIGNALED(status)) {
		pr_err("Spfs with pid %d was killed by %d\n", pid, WTERMSIG(status));
		return -ECANCELED;
	}

	if (WEXITSTATUS(status)) {
		pr_err("Spfs with pid %d exited with error %d\n", pid, WEXITSTATUS(status));
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

	if (mount_spfs(ctx->work_dir, ctx->mountpoint))
		return -EINVAL;

	if (ctx->daemonize) {
		if (daemon(0, 0)) {
			pr_perror("failed to daemonize");
			return -errno;
		}
	}

	return reliable_socket_loop(ctx->sock, NULL, spfs_manager_packet_handler);
}
