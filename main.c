#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <libgen.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <sys/sendfile.h>

#include "manager/swapfd.h"
#include "include/ptrace.h"

#define SRC_FILE "src.txt"
#define SRC_FILE2 "src2.txt"
#define DST_FILE "dst.txt"
#define DST_FILE2 "dst2.txt"

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

static int copy_exe(void)
{
	int exe, new_exe, ret;

	exe = open("/proc/self/exe", O_RDONLY);
	if (exe < 0) {
		perror("Can't open exe");
		return -1;
	}

	new_exe = open("/tmp/test_exe", O_RDWR|O_CREAT, 0777);
	if (new_exe < 0) {
		perror("Can't create exe");
		return -1;
	}

	while ((ret = sendfile(new_exe, exe, NULL, 1024)) > 0)
		;
	if (ret < 0) {
		perror("sendfile");
		return -1;
	}

	close(exe);
	return new_exe;
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
	void *addr;

	if (set_locks(fd) < 0) {
		perror("Can't set locks");
	}

	addr = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		perror("Can't mmap");
		return;
	}
	printf("Setting address %lx\n", (unsigned long)addr);

	addr = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		perror("Can't mmap");
		return;
	}
	printf("Setting address %lx\n", (unsigned long)addr);

	if (write(pipe_fd[1], &addr, sizeof(addr)) != sizeof(addr)) {
		perror("Can't write");
		return;
	}

	while (1)
		sleep(10);
}

int main()
{
	int src[3], dst[3], ret, exe, cwd_fd;
	unsigned long addr = 0x12345678;
	unsigned size = sizeof(addr);
	struct swapfd_exchange se;
	pid_t child;
	int fd[2];

	memset(&se, 0, sizeof(se));

	if (unlink(DST_FILE) < 0)
		printf("Can't unlink\n");
	if (unlink(SRC_FILE) < 0)
		printf("Can't unlink\n");
	src[0] = open(SRC_FILE, O_RDWR|O_CREAT|O_CLOEXEC, 0777);
	dst[0] = open(DST_FILE, O_RDWR|O_CREAT, 0777);
	src[1] = open(SRC_FILE2, O_RDWR|O_CREAT|O_CLOEXEC, 0777);
	dst[1] = open(DST_FILE2, O_RDWR|O_CREAT, 0777);
	src[2] = open("/proc/self/exe", O_RDONLY);
	dst[2] = exe = copy_exe();
	cwd_fd = open("/tmp", O_RDONLY);

	if (src[0] < 0 || dst[0] < 0 || src[1] < 0 || dst[1] < 0 || src[2] < 0 || dst[2] < 0 || cwd_fd < 0) {
		perror("main: Can't open");
		return 1;
	}
	if (write(dst[0], &addr, size) != size) {
		perror("Can't write");
		return 1;
	}
	if (write(src[0], &addr, size) != size) {
		perror("Can't write");
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
		close(dst[0]);
		close(dst[1]);
		close(dst[2]);
		close(cwd_fd);
		do_something(fd, src[0]);
		return 0;
	}

	ret = 1;
	if (read(fd[0], &addr, size) != size) {
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

	se.pid		= child;

	se.addr		= &addr;
	se.addr_fd	= &dst[0];
	se.naddr	= 1;

	se.src_fd	= src;
	se.dst_fd	= dst;
	se.nfd		= 3;

	se.exe_fd	= exe;
	se.cwd_fd	= cwd_fd;
	se.root		= "/tmp";

	if (swapfd_tracee(&se) == 0)
		ret = 0;
out_detach:
	detach_from_task(child);
	/* Exit point */
out_kill:
	kill(child, SIGTERM);
	return ret;
}
