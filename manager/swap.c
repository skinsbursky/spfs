#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>

#include "include/log.h"
#include "include/util.h"

#include "swap.h"
#include "spfs.h"
#include "swapfd.h"

static bool test_fd(pid_t pid, int fd, char *path, void *data)
{
	struct spfs_info_s *info = data;
	struct stat st;
	char fd_path[PATH_MAX];

	sprintf(fd_path, "/proc/%d/fd/%d", pid, fd);

	if (stat(fd_path, &st)) {
		switch (errno) {
			case ENOENT:
			case ENOTDIR:
				break;
			default:
				pr_perror("failed to stat '%s'", fd_path);
		}
		return false;
	}
	if (st.st_dev != info->spfs_stat.st_dev)
		return false;

	pr_debug("replacing %s (-> %s)\n", fd_path, path);

	return true;
}

static void fd_path(pid_t pid, char *name, void *data)
{
	struct spfs_info_s *info = data;
	char tmp[PATH_MAX];

	snprintf(tmp, PATH_MAX, "%s/%s", info->mountpoint, name);
	strcpy(name, tmp);
}

int do_swap_fds(struct spfs_info_s *info, char *pids_list)
{
	char *pid;
	int err = 0;

	while ((pid = strsep(&pids_list, "\n")) != NULL) {
		long p;

		if (!strlen(pid))
			continue;

		err = xatol(pid, &p);
		if (err) {
			pr_err("failed to convert pid %s to number\n", pid);
			break;
		}

		err = swapfd(p, test_fd, fd_path, info);
		if (err)
			pr_err("failed to replace process %d fds: %d\n", p, err);
	}

	return err;
}

