#include <signal.h>
#include <errno.h>
#include <poll.h>

#include "include/ipc.h"
#include "include/util.h"
#include "include/log.h"

int report_status(int pipe, int status)
{
	if (write(pipe, &status, sizeof(status)) < 0) {
		pr_perror("failed to write to fd %d", pipe);
		return -errno;
	}
	return 0;
}

static int poll_child_status(int pipe)
{
	struct pollfd pfd = {
		.fd = pipe,
		.events = POLLIN | POLLERR | POLLHUP,
		.revents = 0,
	};
	int timeout_ms = 5000;
	int res;

	res = poll(&pfd, 1, timeout_ms);
	if (res < 0) {
		res = -errno;
		pr_crit("poll returned %d\n", errno);
		return res;
	}

	if (!res) {
		pr_crit("Child wasn't ready for %d ms.\n"
		       "Something bad happened\n", timeout_ms);
		return -ETIMEDOUT;
	}
	if (pfd.revents & POLLIN)
		return 0;

	if (pfd.revents & POLLERR)
		pr_crit("poll return POLERR\n");
	else if (pfd.revents & POLLHUP)
		pr_crit("poll return POLHUP\n");
	return -1;
}

int kill_child_and_collect(int pid)
{
	int status;
	int signal = SIGKILL;

	pr_info("Killing child %d\n", pid);
	if (kill(pid, signal)) {
		switch (errno) {
			case EINVAL:
				pr_err("Wrong signal?!\n");
				return -EINVAL;
			case EPERM:
				pr_err("Can't kill own child?!\n");
				return -EPERM;
			case ESRCH:
				pr_err("Process doesn't exist (or dead).\n");
				break;
		}
	}

	if (collect_child(pid, &status))
		return -ECHILD;

	return status;
}

int wait_child_report(int pipe)
{
	int err;

	err = poll_child_status(pipe);
	if (!err) {
		ssize_t bytes;

		bytes = read(pipe, &err, sizeof(err));
		if (bytes < 0) {
			pr_perror("failed to read from control pipe");
			err = -errno;
		}
		if (bytes != sizeof(err)) {
			pr_err("Read less than expected\n");
			return -EINTR;
		}
	}
	return err;
}

