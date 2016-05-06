#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <libgen.h>
#include <limits.h>
#include <string.h>
#include <errno.h>

#include "manager/swapfd.h"

#define SRC_FILE "src.txt"
#define DST_FILE "dst.txt"

#define CGROUP_DIR "/sys/fs/cgroup/freezer/user/kirill/3"

static int move_to_freezer_cgroup(pid_t child)
{
	char path[PATH_MAX], buf[16];
	int fd, len, ret = 0;

	sprintf(path, "%s/cgroup.procs", CGROUP_DIR);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		perror("Can't open cgroup.procs");
		return -1;
	}

	sprintf(buf, "%d", child);

	len = strlen(buf);
	if (write(fd, buf, len) != len) {
		perror("Can't move to cgroup");
		ret = -1;
	}

	close(fd);
	return ret;
}

static int change_cgroup_state(const char *state)
{
	char path[PATH_MAX];
	int fd, len, ret = 0;

	sprintf(path, "%s/freezer.state", CGROUP_DIR);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		perror("Can't open cgroup.state");
		return -1;
	}

	len = strlen(state);
	if (write(fd, state, len) != len) {
		fprintf(stderr, "Can't make cgroup %s, errno=%d\n", state, errno);
		ret = -1;
	}

	close(fd);
	return ret;	
}

static int set_locks(int fd)
{
	struct flock lock;

	memset(&lock, 0, sizeof(struct flock));

	lock.l_type = F_WRLCK;
	lock.l_start=5;
	lock.l_whence = SEEK_SET;
	lock.l_len=0;

	lock.l_pid = getpid();

	if (fcntl(fd, F_SETLK, &lock) < 0)
		return -1;

	lock.l_start=0;
	lock.l_whence = SEEK_SET;
	lock.l_len=2;

	if (fcntl(fd, F_SETLK, &lock) < 0)
		return -1;
	return 0;
}

static void do_something(int *pipe_fd, int fd)
{
	if (set_locks(fd) < 0) {
		perror("Can't set locks");
	}

	if (write(pipe_fd[1], "1", 1) != 1) {
		perror("Can't write");
		return;
	}

	while (1)
		sleep(10);
}

int main()
{
	int src, dst, ret;
	pid_t child;
	char c='\n';
	int fd[2];

	if (unlink(DST_FILE) < 0)
		printf("Can't unlink\n");
	if (unlink(SRC_FILE) < 0)
		printf("Can't unlink\n");
	src = open(SRC_FILE, O_RDWR|O_CREAT|O_CLOEXEC, 0777);
	dst = open(DST_FILE, O_RDWR|O_CREAT, 0777);
	if (src < 0 || dst < 0) {
		perror("main: Can't open");
		return 1;
	}
	if (write(dst, &c, 1) != 1) {
		perror("Can't read");
		return 1;
	}
	if (write(src, &c, 1) != 1) {
		perror("Can't read");
		return 1;
	}

	if (pipe(fd)) {
		perror("Can't pipe");
		return 1;
	}

	child = fork();
	if (child < 0) {
		perror("Can't fork");
		return 1;
	} else if (child == 0) {
		close(dst);
		do_something(fd, src);
		return 0;
	}

	ret = 1;
	if (read(fd[0], &c, 1) != 1) {
		perror("Can't read");
		goto out_kill;
	}

	if (move_to_freezer_cgroup(child) < 0)
		goto out_kill;

	if (change_cgroup_state("FROZEN") < 0)
		goto out_kill;

	/* Entry point */
	if (attach_to_task(child) != child) {
		change_cgroup_state("THAWED");
		goto out_kill;
	}

	if (change_cgroup_state("THAWED") < 0)
		goto out_detach;

	if (wait_task_seized(child) < 0)
		goto out_detach;

	if (swapfd_tracee(child, &src, &dst, 1) == 0)
		ret = 0;
out_detach:
	detach_from_task(child);
	/* Exit point */
out_kill:
	kill(child, SIGTERM);
	return ret;
}
