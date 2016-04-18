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
#include <poll.h>

#include "include/util.h"
#include "include/log.h"
#include "include/socket.h"
#include "include/ipc.h"

#include "spfs/context.h"

#include "context.h"
#include "interface.h"

static int move_to_freezer_root(void)
{
	char *freezer_tasks_path = "/sys/fs/cgroup/freezer/tasks";
	char *process_id;
	int fd, err;
	ssize_t bytes;

	fd = open(freezer_tasks_path, O_WRONLY);
	if (fd == -1) {
		pr_perror("failed to open %s", freezer_tasks_path);
		return -errno;
	}

	err = -ENOMEM;
	process_id = xsprintf("%d", getpid());
	if (!process_id) {
		pr_err("failed to construct string\n");
		goto close_fd;
	}

	bytes = write(fd, process_id, strlen(process_id) + 1);
	if (bytes < 0) {
		pr_perror("failed to write to %s", freezer_tasks_path);
		err = -errno;
		goto free_process_id;
	}
	if (bytes != strlen(process_id) + 1) {
		pr_err("wrote less than expected: %ld\n", bytes);
		err = -EINTR;
		goto free_process_id;

	}

	pr_info("joined freezer root cgroup\n");

	err = 0;

free_process_id:
	free(process_id);
close_fd:
	close(fd);
	return err;
}

int main(int argc, char *argv[])
{
	struct spfs_manager_context_s *ctx;

	ctx = create_context(argc, argv);
	if (!ctx)
		return -1;

	if (move_to_freezer_root()) {
		pr_err("failed to move self to root freezer cgroup\n");
		return -1;
	}

	if (ctx->daemonize) {
		if (daemon(1, 1)) {
			pr_perror("failed to daemonize");
			return -errno;
		}
	}

	return reliable_socket_loop(ctx->sock, ctx, false, spfs_manager_packet_handler);
}
