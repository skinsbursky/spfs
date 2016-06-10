#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "include/log.h"
#include "include/namespaces.h"

char *ns_names[NS_MAX] = {
	[NS_UTS] = "uts",
	[NS_MNT] = "mnt",
	[NS_NET] = "net",
	[NS_PID] = "pid",
	[NS_USER] = "user"
};

int open_ns(pid_t pid, const char *ns_type)
{
	int fd;
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "/proc/%d/ns/%s", pid, ns_type);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		pr_perror("failed to open %s", path);
		return -errno;
	}
	return fd;
}

int set_namespaces(int *ns_fds, unsigned ns_mask)
{
	int ns_type, err;

	if (!ns_fds)
		return 0;

	if (!ns_mask) {
		pr_err("ns_mask is empty\n");
		return -EINVAL;
	}

	for (ns_type = NS_UTS; ns_type < NS_MAX; ns_type++) {
		if ((ns_mask & (1 << ns_type)) == 0)
			continue;

		if (ns_fds[ns_type] < 0) {
			pr_err("failed to set %s ns: fd is closed\n",
					ns_names[ns_type]);
			continue;
		}

		err = setns(ns_fds[ns_type], 0);
		if (err) {
			pr_perror("failed to set ns by fd %d", ns_fds[ns_type]);
			break;
		}
	}
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
	int err, ns_type;

	for (ns_type = NS_UTS; ns_type < NS_MAX; ns_type++) {
		err = open_ns(pid, ns_names[ns_type]);
		if (err < 0)
			goto close_saved_fd;
		ns_fds[ns_type] = err;
	}

	return 0;

close_saved_fd:
	(void)close_namespaces(ns_fds);
	return err;
}
