#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "include/log.h"
#include "include/namespaces.h"

char *ns_names[NS_MAX] = {
	[NS_UTS] = "uts",
	[NS_MNT] = "mnt",
	[NS_NET] = "net",
	[NS_PID] = "pid",
	[NS_USER] = "user"
};

int open_ns(pid_t pid, nstype_t ns_type)
{
	int fd;
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "/proc/%d/ns/%s", pid, ns_names[ns_type]);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("failed to open %s", path);
		return -errno;
	}
	return fd;
}

int set_ns(int ns_fd)
{
	int err;

	err = setns(ns_fd, 0);
	if (err) {
		pr_perror("failed to set ns by fd %d", ns_fd);
		return -errno;
	}
	return 0;
}

int set_namespaces(const int *ns_fds, unsigned ns_mask)
{
	int ns_type, err = 0;

	if (!ns_fds)
		return 0;

	for (ns_type = NS_UTS; ns_type < NS_MAX; ns_type++) {
		if ((ns_mask & (1 << ns_type)) == 0)
			continue;

		if (ns_fds[ns_type] < 0) {
			pr_err("failed to set %s ns: fd is closed\n",
					ns_names[ns_type]);
			continue;
		}

		err = set_ns(ns_fds[ns_type]);
		if (err)
			break;
	}
	return err;
}

static bool skip_ns(int ns_fd, int ns_type)
{
	struct stat fd_ns_st, self_ns_st;
	char ns_path[] = "/proc/self/ns/XXXXX";

	if (fstat(ns_fd, &fd_ns_st) == -1) {
		pr_perror("failed to stat /proc/self/fd/%d", ns_fd);
		return true;
	}

	snprintf(ns_path, strlen(ns_path), "/proc/self/ns/%s", ns_names[ns_type]);
	if (stat(ns_path, &self_ns_st) == -1) {
		pr_perror("failed to stat %s", ns_path);
		sleep(1000);
		return true;
	}

	return !memcmp(&fd_ns_st, &self_ns_st, sizeof(struct stat));
}

int join_namespaces(const int *ns_fds, unsigned ns_mask, unsigned *rst_mask)
{
	int err = 0;
	unsigned real_mask = 0;

	if (ns_fds) {
		int ns_type;

		if (!ns_mask) {
			pr_err("ns_mask is empty\n");
			return -EINVAL;
		}

		for (ns_type = NS_UTS; ns_type < NS_MAX; ns_type++) {
			if ((ns_mask & (1 << ns_type)) == 0)
				continue;

			if (skip_ns(ns_fds[ns_type], ns_type)) {
				pr_debug("Skipping %s namespace\n", ns_names[ns_type]);
				continue;
			}

			real_mask |= 1 << ns_type;
		}

		err = set_namespaces(ns_fds, real_mask);
	}

	if (rst_mask)
		*rst_mask = real_mask;
	return err;
}

int close_namespaces(int *ns_fds)
{
	int ns_type;

	if (!ns_fds)
		return 0;

	for (ns_type = NS_UTS; ns_type < NS_MAX; ns_type++) {
		if (ns_fds[ns_type] < 0)
			continue;
		close(ns_fds[ns_type]);
		ns_fds[ns_type] = -1;
	}
	return 0;
}

int open_namespaces(pid_t pid, int *ns_fds)
{
	int err;
	nstype_t ns_type;

	for (ns_type = NS_UTS; ns_type < NS_MAX; ns_type++) {
		err = open_ns(pid, ns_type);
		if (err < 0)
			goto close_saved_fd;
		ns_fds[ns_type] = err;
	}

	return 0;

close_saved_fd:
	(void)close_namespaces(ns_fds);
	return err;
}
