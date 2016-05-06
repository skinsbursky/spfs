#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <libgen.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <syscall.h>
#include <stdint.h>

#include "include/ptrace.h"
#include "include/pie-util-fd.h"

#include "swapfd.h"

#define MMAP_SIZE PATH_MAX

static void *find_mapping(pid_t pid)
{
	char path[strlen("/proc/4294967295/maps") + 1];
	void *result = MAP_FAILED;
	size_t size = 0;
	char *line;
	FILE *fp;

	sprintf(path, "/proc/%d/maps", pid);
	fp = fopen(path, "r");
	if (!fp) {
		printf("Can't open %s\n", path);
		return result;
	}

	while (getline(&line, &size, fp) != -1) {
		unsigned long start, end;
		char r, w, x;
		int ret;

		ret = sscanf(line, "%lx%*c%lx %c%c%c", &start, &end, &r, &w, &x);
		if (ret != 5) {
			printf("Can't parse line: %s", line);
			continue;
		}

		if (x != 'x')
			continue;

		printf("Found: start=%08lx, end=%08lx, r=%c, w=%c, x=%c\n",
				start, end, r, w, x);
		result = (void *)start;
		break;
	}

	free(line);
	fclose(fp);

	return result;
}

static void destroy_parasite_ctl(pid_t pid, struct parasite_ctl *ctl);

static void destroy_dgram_socket(struct parasite_ctl *ctl)
{
	unsigned long sret;
	int ret;

	if (ctl->local_sockfd >= 0) {
		close(ctl->local_sockfd);
		ctl->local_sockfd = -1;
	}

	if (ctl->remote_sockfd < 0)
		return;

	ret = syscall_seized(ctl, __NR_close, &sret,
			     ctl->remote_sockfd, 0, 0, 0, 0, 0);
	if (ret || sret)
		fprintf(stderr, "Can't destroy dgram socket\n");
	else
		ctl->remote_sockfd = -1;
}
static int set_dgram_socket(struct parasite_ctl *ctl)
{
	struct sockaddr_un *addr = (void *)ctl->local_map;
	int fd, ret, i, len, len2, err;
	unsigned long sret;

	ret = syscall_seized(ctl, __NR_socket, &sret,
			     AF_UNIX, SOCK_DGRAM, 0, 0, 0, 0);
	fd = (int)(long)sret;
	if (ret < 0 || fd < 0) {
		fprintf(stderr, "Can't create dgram socket: %d %d", ret, fd);
		return -1;
	}
	ctl->remote_sockfd = fd;

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	len = sprintf(addr->sun_path + 1, "SWAPFD-%d-", ctl->pid) + 1;
	addr->sun_path[0] = '\0';

	for (i = 0; i < 1000; i++) {
		len2 = sprintf(addr->sun_path + len, "%x", i);
		ret = syscall_seized(ctl, __NR_bind, &sret,
				     fd, (unsigned long)ctl->remote_map,
				     len + len2 + sizeof(addr->sun_family),
				     0, 0, 0);
		err = (int)(long)sret;
		if (err == -EADDRINUSE)
			continue;
		if (ret < 0 || err < 0) {
			fprintf(stderr, "Can't bind: %d %d\n", ret, err);
			break;
		}

		ctl->local_sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (ctl->local_sockfd < 0) {
			fprintf(stderr, "Can't create local sock: %d\n", errno);
			break;
		}

		memcpy(&ctl->addr, addr, sizeof(*addr));
		ctl->addrlen = len + len2 + sizeof(addr->sun_family);
		printf("Set socket %s\n", addr->sun_path);

		return 0;
	}

	fprintf(stderr, "Can't set dgram sockets\n");
	destroy_dgram_socket(ctl);
	return -1;
}

static int set_parasite_ctl(pid_t pid, struct parasite_ctl **ret_ctl)
{
	char path[] = "/proc/XXXXXXXXXX/fd/XXXXXXXXXX";
	void *addr = find_mapping(pid);
	void *where = addr + BUILTIN_SYSCALL_SIZE;
	uint8_t orig_code[] = "SWAPMFD";
	unsigned long sret = -ENOSYS;
	struct parasite_ctl *ctl;
	int ret, fd, lfd;

	if (addr == MAP_FAILED) {
		printf("Can't find a useful mapping, pid=%d\n", pid);
		return -ENOMEM;
	}

	ctl = malloc(sizeof(*ctl));
	if (!ctl) {
		printf("Can't alloc ctl\n");
		return -ENOMEM;
	}
	ctl->pid = pid;
	ctl->syscall_ip = (unsigned long)addr;
	ctl->remote_sockfd = -1;
	ctl->local_sockfd = -1;

        if (get_thread_ctx(pid, &ctl->orig))
		goto err_free;

	if (ptrace_swap_area(pid, where, (void *)orig_code, sizeof(orig_code))) {
		printf("Can't inject memfd args (pid: %d)\n", pid);
		goto err_free;
	}

	ret = syscall_seized(ctl, __NR_memfd_create, &sret,
			     (unsigned long)where, 0, 0, 0, 0, 0);

	if (ptrace_poke_area(pid, orig_code, where, sizeof(orig_code))) {
		fd = (int)(long)sret;
		if (fd >= 0)
			syscall_seized(ctl, __NR_close, &sret, fd, 0, 0, 0, 0, 0);
		printf("Can't restore memfd args (pid: %d)\n", pid);
		goto err_free;
	}

	if (ret < 0)
		goto err_free;

	fd = (int)(long)sret;
	if (fd < 0)
		goto err_free;

	ctl->map_length = MMAP_SIZE;
	sprintf(path, "/proc/%d/fd/%d", pid, fd);
	lfd = open(path, O_RDWR);
	if (lfd < 0) {
		printf("Can't open %s\n", path);
		goto err_cure;
	}

	if (ftruncate(lfd, ctl->map_length) < 0) {
		printf("Fail to truncate memfd for parasite\n");
		goto err_cure;
	}

	ctl->remote_map = mmap_seized(ctl, NULL, MMAP_SIZE,
				      PROT_READ | PROT_WRITE | PROT_EXEC,
				      MAP_FILE | MAP_SHARED, fd, 0);
	if (!ctl->remote_map) {
		printf("Can't rmap memfd for parasite blob\n");
		goto err_curef;
	}

	ctl->local_map = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_FILE, lfd, 0);
	if (ctl->local_map == MAP_FAILED) {
		printf("Can't lmap memfd for parasite blob\n");
		goto err_curef;
	}

	syscall_seized(ctl, __NR_close, &sret, fd, 0, 0, 0, 0, 0);
	close(lfd);

	if (set_dgram_socket(ctl) < 0) {
		destroy_parasite_ctl(pid, ctl);
		goto err_free;
	}

	*ret_ctl = ctl;
	printf("Set up parasite blob using memfd\n");
	return 0;

err_curef:
	close(lfd);
err_cure:
	syscall_seized(ctl, __NR_close, &sret, fd, 0, 0, 0, 0, 0);
err_free:
	free(ctl);
	return -1;
}

static void destroy_parasite_ctl(pid_t pid, struct parasite_ctl *ctl)
{
	unsigned long sret;
	int ret;

	destroy_dgram_socket(ctl);

	ret = syscall_seized(ctl, __NR_munmap, &sret, (unsigned long)ctl->remote_map, ctl->map_length, 0, 0, 0, 0);
	if (ret || ((int)(long)sret) < 0)
		printf("Can't munmap remote file\n");

	ret = munmap(ctl->local_map, ctl->map_length);
	if (ret)
		printf("Can't munmap local map\n");
}

/* Get pos and flags from just open fdinfo file */
static int get_fd_mode(FILE *fp, long long int *pos, mode_t *mode)
{
	int i = 0, ret = 0;
	char *line = NULL;
	size_t size = 0;

	while (getline(&line, &size, fp) != -1) {
		if (strncmp(line, "pos:\t", 5) == 0)
			sscanf(line + 5, "%lli", pos);
		else if (strncmp(line, "flags:\t0", 8) == 0)
			sscanf(line + 8, "%o", mode);
		else {
			printf("Can't parse fdinfo file\n");
			ret = -1;
			break;
		}
		if (++i == 2)
			break;
	}
	printf("pos=%lli, mode=0%o\n", *pos, *mode);
	free(line);
	return ret;
}

static void close_fds(int fd[], int num)
{
	while (num > 0)
		if (fd[--num] >= 0) {
			close(fd[num]);
			fd[num] = -1;
		}
}

static int send_dst_fds(struct parasite_ctl *ctl, int fd[], int num)
{
	int ret;

	ret = send_fds(ctl->local_sockfd, &ctl->addr, ctl->addrlen, fd, num, false);

	return ret;
}

/* Receive next fd from receive queue of remote_sockfd */
static int get_next_fd(struct parasite_ctl *ctl)
{
	return recv_fd(ctl);
}

struct lock {
	loff_t start, end;
	short type;
	bool is_posix;
	struct lock *next;
};

static int make_posix_lock(struct parasite_ctl *ctl, int fd, short type, loff_t start, loff_t end)
{
	unsigned long sret;
	struct flock lock;
	int ret;

	lock.l_type = type;
	lock.l_start = start;
	lock.l_whence = SEEK_SET;
	if (end == (loff_t)-1)
		lock.l_len = 0;
	else
		lock.l_len = end - start + 1;
	lock.l_pid = ctl->pid;

	memcpy((char *)ctl->local_map, (void *)&lock, sizeof(lock));

	ret = syscall_seized(ctl, __NR_fcntl, &sret, fd, F_SETLK, (unsigned long)ctl->remote_map, 0, 0, 0);
	if (ret < 0 || ((int)(long)sret) < 0) {
		printf("Can't create posix lock, pid=%d, ret=%d, sret=%d\n", ctl->pid, ret, ((int)(long)sret));
		return -1;
	}

	return 0;
}

static int make_flock_lock(struct parasite_ctl *ctl, int fd, short type)
{
	unsigned long sret;
	int ret;

	switch (type) {
	case F_RDLCK:
		type = LOCK_SH;
		break;
	case F_WRLCK:
		type = LOCK_EX;
		break;
	default:
		printf("Wrong flock type\n");
		return -1;
	}

	ret = syscall_seized(ctl, __NR_flock, &sret, fd, type, 0, 0, 0, 0);
	if (ret < 0 || ((int)(long)sret) < 0) {
		printf("Can't create flock, pid=%d, ret=%d, sret=%d\n", ctl->pid, ret, ((int)(long)sret));
		return -1;
	}

	return 0;
}

static int get_flocks(struct parasite_ctl *ctl, FILE *fp, struct lock *head)
{
	struct lock *prev = head, *new;
	char *line = NULL;
	size_t size = 0;
	int ret = 0;

	while (getline(&line, &size, fp) != -1) {
		loff_t start, end;
		char *p = line;
		bool is_posix;
		short type;
		if (strncmp(p, "lock:\t", 6) != 0)
			continue;
		p += 6;
		p = strchr(p, ':');
		if (!p) {
			printf("Can't parse fdinfo file\n");
			ret = -1;
			break;
		}
		p++;

		if (strncmp(p, " POSIX  ADVISORY  ", 18) == 0)
			is_posix = true;
		else if (strncmp(p, " FLOCK  ADVISORY  ", 18) == 0)
			is_posix = false;
		else {
			printf("Unknown lock type: %s", line);
			ret = -1;
			break;
		}
		p += 18;

		if (strncmp(p, "READ  ", 6) == 0)
			type = F_RDLCK;
		else if (strncmp(p, "WRITE ", 6) == 0)
			type = F_WRLCK;
		else {
			printf("Unknown lock type: %s", line);
			ret = -1;
			break;
		}
		p += 6;

		p = strrchr(p, ':');
		if (!p) {
			printf("Can't parse flock %s", line);
			ret = -1;
			break;
		}
		p++;

		if (sscanf(p, "%*d %ld %ld", &start, &end) == 1) {
			/* end is EOF */
			end = (loff_t)-1;
		}
		printf("type=%u, start=%ld, end=%ld\n", type, start, end);

		new = malloc(sizeof(*new));
		if (!new) {
			printf("Can't do malloc()\n");
			ret = -1;
			break;
		}

		new->is_posix = is_posix;
		new->type = type;
		new->start = start;
		new->end = end;
		new->next = NULL;
		prev->next = new;
		prev = new;
	}

	free(line);
	return ret;
}

/* Replace a fd, having number @src_fd, with a fd, received from socket */
static int changefd(struct parasite_ctl *ctl, pid_t pid, int src_fd, int dst_fd)
{
	char fdinfo[] = "/proc/XXXXXXXXXX/fdinfo/XXXXXXXXXX";
	FILE *fp;
	long long int f_pos;
	unsigned long sret;
	mode_t mode;
	int new_fd, ret, exit_code = 0;
	struct lock head = {.next = NULL,}, *ptr;
	bool need_lseek;
	struct stat st;

	if (fstat(dst_fd, &st) < 0) {
		perror("Can't stat on dst_fd");
		return -1;
	}
	need_lseek = (st.st_mode & (S_IFREG | S_IFBLK | S_IFDIR)) != 0;

	sprintf(fdinfo, "/proc/%d/fdinfo/%d", pid, src_fd);
	fp = fopen(fdinfo, "r");
	if (!fp) {
		printf("Can't open %s\n", fdinfo);
		exit_code = -1;
		goto out;
	}

	if (get_fd_mode(fp, &f_pos, &mode) < 0) {
		exit_code = -1;
		goto out;
	}

	if (get_flocks(ctl, fp, &head) < 0) {
		exit_code = -1;
		goto out;
	}

	new_fd = get_next_fd(ctl);
	if (new_fd < 0) {
		exit_code = -1;
		goto out;
	}

	ret = syscall_seized(ctl, __NR_dup2, &sret, new_fd, src_fd, 0, 0, 0, 0);
	if (ret < 0 || ((int)(long)sret) < 0) {
		printf("Can't dup2(%d, %d). pid=%d\n", new_fd, src_fd, pid);
		exit_code = -1;
	}

	ret = syscall_seized(ctl, __NR_close, &sret, new_fd, 0, 0, 0, 0, 0);
	if (ret < 0 || sret != 0) {
		printf("Can't close temporary fd, pid=%d\n", pid);
		exit_code = -1;
	}

	if (exit_code == 0 && need_lseek) {
		ret = syscall_seized(ctl, __NR_lseek, &sret, src_fd, f_pos, SEEK_SET, 0, 0, 0);
		if (ret < 0 || ((int)(long)sret) < 0) {
			printf("Can't lseek pid=%d, fd=%d\n", pid, src_fd);
			exit_code = -1;
		}
	}
out:
	ptr = head.next;
	while (ptr) {
		struct lock *prev = ptr;
		if (exit_code == 0) {
			if (ptr->is_posix)
				ret = make_posix_lock(ctl, src_fd, ptr->type, ptr->start, ptr->end);
			else
				ret = make_flock_lock(ctl, src_fd, ptr->type);
		}
		if (ret)
			exit_code = ret;
		ptr = ptr->next;
		free(prev);
	}

	if (fp)
		fclose(fp);
	return exit_code;
}

/* Replace tracee's remote @src_fd[] with caller's local @dst_fd */
int swapfd_tracee(pid_t pid, int src_fd[], int dst_fd[], int num)
{
	struct parasite_ctl *ctl;
	int i, ret;

	ret = set_parasite_ctl(pid, &ctl);
	if (ret < 0) {
		goto out_close;
	}

	ret = send_dst_fds(ctl, dst_fd, num);
	if (ret < 0)
		goto out_destroy;

	for (i = 0; i < num; i++) {
		ret = changefd(ctl, pid, src_fd[i], dst_fd[i]);
		if (ret < 0)
			goto out_destroy;
	}

out_destroy:
	destroy_parasite_ctl(pid, ctl);
out_close:
	close_fds(dst_fd, num);
	return ret;
}

static int seize_catch_task(pid_t pid)
{
	int ret;

	ret = ptrace(PTRACE_SEIZE, pid, NULL, 0);
	if (ret) {
		/* Error or task is exiting */
		fprintf(stderr, "Can't seize task %d", pid);
		return -1;
	}

	ret = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
	if (ret < 0) {
		/* Currently this happens only if task is exiting */
		fprintf(stderr, "Can't interrupt task %d", pid);

		if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
			perror("Can't detach");
	}

	return ret;

}

/*
 *  Should be called for a frozen task. Returns @pid
 *  if we've attached; and 0 if we meet kernel thread.
 */
pid_t attach_to_task(pid_t pid)
{
	int ret;

	ret = seize_catch_task(pid);
	if (ret < 0) {
		char buf[] = "/proc/XXXXXXXXXX/exe";
		struct stat st;

		/* skip kernel threads */ 
		snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
		if (stat(buf, &st) == -1 && errno == ENOENT)
			return 0;

		/* fails on a zombie */
		fprintf(stderr, "zombie found while seizing\n");
		return (pid_t)-1;
	}

	return pid;
}

int detach_from_task(pid_t pid)
{
	int status, ret;

	ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (ret) {
		fprintf(stderr, "Can't detach from %d\n", pid);
		/* A process may be killed by SIGKILL */
		if (wait4(pid, &status, __WALL, NULL) == pid)
			ret = 0;
		else
			fprintf(stderr, "Unable to wait %d\n", pid);
	}

	return ret;

}

int wait_task_seized(pid_t pid)
{
	int status, ret;
	siginfo_t si;

try_again:
	ret = wait4(pid, &status, __WALL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Can't wait %d\n", pid);
		return ret;
	}

	if (WIFEXITED(status) || WIFSIGNALED(status)) {
		fprintf(stderr, "Task exited unexpected %d\n", pid);
		return -1;
	}

	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "SEIZE %d: task not stopped after seize\n", pid);
		return -1;
	}

	ret = ptrace(PTRACE_GETSIGINFO, pid, NULL, &si);
	if (ret < 0) {
		fprintf(stderr, "SEIZE %d: can't read signfo", pid);
		return -1;
	}

	if (SI_EVENT(si.si_code) != PTRACE_EVENT_STOP) {
		/*
		 * Kernel notifies us about the task being seized received some
		 * event other than the STOP, i.e. -- a signal. Let the task
		 * handle one and repeat.
		 */
		if (ptrace(PTRACE_CONT, pid, NULL,
					(void *)(unsigned long)si.si_signo)) {
			fprintf(stderr, "Can't continue signal handling, aborting, pid=%d, errno=%d", pid, errno);
			return -1;
		}

		ret = 0;
		goto try_again;
	}

	return 0;
}
