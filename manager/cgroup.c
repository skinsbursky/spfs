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

static int move_to_cgroup_fd(int fd, const char *cg)
{
	char cgroup_tasks_path[PATH_MAX];
	char *process_id;
	int err;
	ssize_t bytes;

	process_id = xsprintf("%d", getpid());
	if (!process_id) {
		pr_err("failed to construct string\n");
		return -ENOMEM;
	}

	bytes = write(fd, process_id, strlen(process_id) + 1);
	if (bytes < 0) {
		pr_perror("failed to write to %s", cgroup_tasks_path);
		err = -errno;
		goto free_process_id;
	}
	if (bytes != strlen(process_id) + 1) {
		pr_err("wrote less than expected: %ld\n", bytes);
		err = -EINTR;
		goto free_process_id;

	}

	err = 0;

free_process_id:
	free(process_id);
	return err;
}

int move_to_cgroup(const char *controller, const char *cg)
{
	char cgroup_tasks_path[PATH_MAX];
	int fd, err;

	snprintf(cgroup_tasks_path, PATH_MAX, "/sys/fs/cgroup/%s%s/tasks", controller, cg);

	fd = open(cgroup_tasks_path, O_WRONLY);
	if (fd == -1) {
		pr_perror("failed to open %s", cgroup_tasks_path);
		return -errno;
	}

	err = move_to_cgroup_fd(fd, cg);
	if (err)
		pr_err("failed to move self to root %s%s cgroup\n", controller, cg);
	else
		pr_debug("joined \"%s%s\" cgroup\n", controller, cg);

	close(fd);
	return err;
}


