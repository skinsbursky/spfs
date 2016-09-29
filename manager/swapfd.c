#include <sys/sendfile.h>
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
#include <linux/prctl.h>

#include "include/ptrace.h"
#include "include/pie-util-fd.h"
#include "include/log.h"

#include "swapfd.h"

#define MMAP_SIZE (PATH_MAX + BUILTIN_SYSCALL_SIZE)
#define MAX_BIND_ATTEMPTS	1000

static void *find_mapping(pid_t pid)
{
	char path[PATH_MAX];
	void *result = MAP_FAILED;
	size_t size = 0;
	char *line;
	FILE *fp;

	sprintf(path, "/proc/%d/maps", pid);
	fp = fopen(path, "r");
	if (!fp) {
		pr_perror("Can't open %s", path);
		return result;
	}

	while (getline(&line, &size, fp) != -1) {
		unsigned long start;
		char x, p;
		int ret;

		ret = sscanf(line, "%lx-%*x %*c%*c%c%c", &start, &x, &p);
		if (ret != 3) {
			pr_err("Can't parse line: %s", line);
			result = MAP_FAILED;
			break;
		}

		if (p != 'p')
			continue;

		if (x != 'x' || start > TASK_SIZE)
			continue;

		result = (void *)start;
		pr_debug("Using mapping: %s\n", line);
		break;
	}

	free(line);
	fclose(fp);

	return result;
}

static int copy_private_content(struct parasite_ctl *ctl, unsigned long to,
				unsigned long from, unsigned long size)
{
	char path[] = "/proc/XXXXXXXXXX/mem";
	int src = -1, dst = -1, ret = -1;
	ssize_t copied = 0, count;
	unsigned int size_map;
	char buf[PAGE_SIZE];
	uint64_t *map;

	if (size & (PAGE_SIZE - 1)) {
		pr_err("Not aligned size: %lu\n", size);
		return -EFAULT;
	}

	size_map = PAGEMAP_LEN(size);
	map = malloc(size_map);
	if (!map) {
		pr_perror("Can't malloc() %u for %d\n", size_map, ctl->pid);
		return -ENOMEM;
	}
	if (pread(ctl->pagemap_fd, map, size_map, PAGEMAP_PFN_OFF(from)) != size_map) {
		pr_perror("Can't read %d's pagemap file", ctl->pid);
		goto free_map;
	}

	sprintf(path, "/proc/%d/mem", ctl->pid);
	src = open(path, O_RDONLY);
	if (src < 0) {
		pr_perror("Can't open %s for read", path);
		goto free_map;
	}

	dst = open(path, O_WRONLY);
	if (dst < 0) {
		pr_perror("Can't open %s for write", path);
		goto close_src;
	}

	do {
		count = PAGE_SIZE;

		if (map[copied/PAGE_SIZE] & PME_PRESENT) {
			count = pread(src, buf, count, from + copied);
			if (count < 0) {
				pr_perror("Can't read from tracee's memory");
				goto out;
			}
			if (count != pwrite(dst, buf, count, to + copied)) {
				pr_perror("Can't write to tracee's memory");
				goto out;
			}
		}
		copied += count;
	} while (copied != size);

	ret = 0;

out:
	close(dst);
close_src:
	close(src);
free_map:
	free(map);
	return ret;
}

static int move_map(struct parasite_ctl *ctl,
		    unsigned long start, unsigned long end, int dst_fd,
		    int prot, int flags, unsigned long long pgoff)
{
	int ret;
	unsigned long sret, addr;
	size_t length = end - start;

	ret = syscall_seized(ctl, __NR_msync, &sret, start, length, MS_SYNC, 0, 0, 0);
	if (ret || sret) {
		pr_err("Can't msync at [%lx; %lx], ret=%d, sret=%d\n",
			start, end, ret, (int)(long)sret);
		return -1;
	}

	pr_debug("        mmap to replace %lx: len=%lx, prot=%x, flags=%x, off=%lx\n",
		 start, length, prot, flags, pgoff);

	addr = (unsigned long)mmap_seized(ctl, 0, length, prot, flags, dst_fd, pgoff);
	if (!addr) {
		pr_err("mmap failed\n");
		return -1;
	}

	if (flags & MAP_PRIVATE) {
		ret = copy_private_content(ctl, addr, start, length);
		if (ret)
			return -1;
	}

	flags = MREMAP_FIXED | MREMAP_MAYMOVE;
	pr_debug("        remapping %lx to %lx, size=%lx\n", addr, start, length);
	ret = syscall_seized(ctl, __NR_mremap, &sret, addr, length, length, flags, start, 0);
	if (ret || IS_ERR_VALUE(sret)) {
		pr_err("Can't remap: ret=%d, sret=%d\n", ret, (int)(long)sret);
		return -1;
	}

	return 0;
}

static int transfer_local_fd(struct parasite_ctl *ctl, int local_fd)
{
	int ret;

	ret = send_fd(ctl, false, local_fd);
	if (ret < 0) {
		pr_err("failed to send local fd %d to process %d\n",
				local_fd, ctl->pid);
		return -1;
	}

	ret = recv_fd(ctl, true);
	if (ret < 0)
		pr_err("failed to receive local fd %d in process %d\n",
				local_fd, ctl->pid);

	return ret;
}

int swap_map(struct parasite_ctl *ctl, int map_fd,
	     unsigned long start, unsigned long end,
	     int prot, int flags, unsigned long long pgoff)
{
	int err, remote_fd;

	remote_fd = transfer_local_fd(ctl, map_fd);
	if (remote_fd < 0)
		return remote_fd;

	err = move_map(ctl, start, end, remote_fd, prot, flags, pgoff);
	if (err)
		return err;

	err = close_seized(ctl, remote_fd);
	if (err)
		pr_err("Can't close temporary fd=%d, pid=%d\n", remote_fd, ctl->pid);

	return err;
}

static void destroy_dgram_socket(struct parasite_ctl *ctl)
{
	int ret;

	if (ctl->local_sockfd >= 0) {
		close(ctl->local_sockfd);
		ctl->local_sockfd = -1;
	}

	if (ctl->remote_sockfd < 0)
		return;

	ret = close_seized(ctl, ctl->remote_sockfd);
	if (ret)
		pr_err("Can't destroy dgram socket\n");
	else
		ctl->remote_sockfd = -1;
}

int is_parasite_sock(struct parasite_ctl *ctl, ino_t ino)
{
	return ctl->remote_sock_ino == ino;
}

static int set_dgram_socket(struct parasite_ctl *ctl)
{
	struct sockaddr_un *addr = (void *)ctl->local_map;
	int fd, ret, i, len, len2, err;
	unsigned long sret;
	socklen_t addrlen;
	char *path = (void *)ctl->local_map;
	struct stat st;

	ret = syscall_seized(ctl, __NR_socket, &sret,
			     AF_UNIX, SOCK_DGRAM, 0, 0, 0, 0);
	fd = (int)(long)sret;
	if (ret < 0 || fd < 0) {
		pr_err("Can't create remote sock: %d %d", ret, fd);
		return -1;
	}
	ctl->remote_sockfd = fd;

	sprintf(path, "/proc/%d/fd/%d", ctl->pid, ctl->remote_sockfd);
	ret = stat(path, &st);
	if (ret) {
		pr_perror("failed to stat %s", path);
		return -errno;
	}
	ctl->remote_sock_ino = st.st_ino;

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	len = sprintf(addr->sun_path + 1, "SWAPFD-remote-%d-", ctl->pid) + 1;
	addr->sun_path[0] = '\0';

	for (i = 0; i < MAX_BIND_ATTEMPTS; i++) {
		len2 = sprintf(addr->sun_path + len, "%x", i);
		addrlen = sizeof(addr->sun_family) + len + len2;

		ret = syscall_seized(ctl, __NR_bind, &sret,
				     fd, (unsigned long)ctl->remote_map,
				     addrlen,
				     0, 0, 0);
		err = (int)(long)sret;
		if (!ret && err == -EADDRINUSE)
			continue;
		if (ret < 0 || err < 0) {
			pr_err("Can't bind remote: %d %d\n", ret, err);
			goto destroy;
		}

		memcpy(&ctl->remote_addr, addr, sizeof(*addr));
		ctl->remote_addrlen = addrlen;
		pr_debug("        Set remote sock %s\n", addr->sun_path + 1);
		break;
	}

	fd = ctl->local_sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		pr_perror("Can't create local sock");
		goto destroy;
	}

	len = sprintf(addr->sun_path + 1, "SWAPFD-local-%d-", ctl->pid) + 1;

	for (i = 0; i < MAX_BIND_ATTEMPTS; i++) {
		len2 = sprintf(addr->sun_path + len, "%x", i);
		addrlen = sizeof(addr->sun_family) + len + len2;

		ret = bind(fd, addr, addrlen);
		if (ret < 0 && errno == -EADDRINUSE)
			continue;
		if (ret < 0) {
			pr_perror("Can't bind local");
			goto destroy;
		}
		memcpy(&ctl->local_addr, addr, sizeof(*addr));
		ctl->local_addrlen = addrlen;
		return 0;
	}
destroy:
	destroy_dgram_socket(ctl);
	return -1;
}

static int parasite_inject_memfd(struct parasite_ctl *ctl, void *where)
{
	uint8_t orig_code[] = "SWAPMFD";
	unsigned long sret = -ENOSYS;
	int ret, fd;

	if (ptrace_swap_area(ctl->pid, where, (void *)orig_code, sizeof(orig_code))) {
		pr_err("Can't inject memfd args (pid: %d)\n", ctl->pid);
		return -1;
	}

	ret = syscall_seized(ctl, __NR_memfd_create, &sret,
			     (unsigned long)where, 0, 0, 0, 0, 0);

	fd = sret;
	if (ptrace_poke_area(ctl->pid, orig_code, where, sizeof(orig_code))) {
		if (fd >= 0)
			close_seized(ctl, fd);
		pr_err("Can't restore memfd args (pid: %d)\n", ctl->pid);
		return -1;
	}

	if (ret < 0 || fd < 0) {
		pr_err("Can't create memfd: %d %d\n", ret, fd);
		return -1;
	}

	return fd;
}

static int parasite_set_map(struct parasite_ctl *ctl, int fd)
{
	char path[] = "/proc/XXXXXXXXXX/fd/XXXXXXXXXX";
	int lfd, err = -EPERM, ret;
	unsigned long sret;

	sprintf(path, "/proc/%d/fd/%d", ctl->pid, fd);
	lfd = open(path, O_RDWR);
	if (lfd < 0) {
		pr_perror("Can't open %s", path);
		return -errno;
	}

	if (ftruncate(lfd, ctl->map_length) < 0) {
		pr_perror("Fail to truncate memfd for parasite");
		err = -errno;
		goto close_lfd;
	}

	ctl->remote_map = mmap_seized(ctl, NULL, MMAP_SIZE,
				      PROT_READ | PROT_WRITE | PROT_EXEC,
				      MAP_FILE | MAP_SHARED, fd, 0);
	if (!ctl->remote_map) {
		pr_err("Can't rmap memfd for parasite blob\n");
		goto close_lfd;
	}

	ctl->local_map = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_FILE, lfd, 0);
	if (ctl->local_map == MAP_FAILED) {
		pr_perror("Can't lmap memfd for parasite blob");
		goto munmap_remote_map;
	}

	err = 0;

close_lfd:
	close(lfd);
	return err;

munmap_remote_map:
	ctl->syscall_ip = ctl->syscall_ip_saved;
	ret = syscall_seized(ctl, __NR_munmap, &sret, (unsigned long)ctl->remote_map, ctl->map_length, 0, 0, 0, 0);
	if (ret || ((int)(long)sret) < 0)
		pr_err("Can't munmap remote file\n");
	goto close_lfd;
}

static int inject_parasite(struct parasite_ctl *ctl, void *addr)
{
	int fd, err;

	fd = parasite_inject_memfd(ctl, addr + BUILTIN_SYSCALL_SIZE);
	if (fd < 0)
		return fd;

	err = parasite_set_map(ctl, fd);

	close_seized(ctl, fd);
	return err;
}

int set_parasite_ctl(pid_t pid, struct parasite_ctl **ret_ctl)
{
	char path[] = "/proc/XXXXXXXXXX/fd/XXXXXXXXXX";
	void *addr;
	struct parasite_ctl *ctl;

	addr = find_mapping(pid);
	if (addr == MAP_FAILED) {
		pr_err("Can't find a useful mapping, pid=%d\n", pid);
		return -ENOMEM;
	}

	ctl = malloc(sizeof(*ctl));
	if (!ctl) {
		pr_err("Can't alloc ctl\n");
		return -ENOMEM;
	}

	ctl->pid = pid;
	ctl->syscall_ip = (unsigned long)addr;
	ctl->syscall_ip_saved = (unsigned long)addr;
	ctl->remote_sockfd = -1;
	ctl->local_sockfd = -1;
	ctl->map_length = MMAP_SIZE;

	sprintf(path, "/proc/%d/pagemap", pid);
	ctl->pagemap_fd = open(path, O_RDONLY);
	if (ctl->pagemap_fd < 0) {
		pr_perror("Can't open pagemap for %d\n", pid);
		goto err_free;
	}

        if (get_thread_ctx(pid, &ctl->orig))
		goto close_pagemap_fd;

	if (inject_parasite(ctl, addr))
		goto close_pagemap_fd;

	/*
	 * Use allocated memory for syscall number, because task's mappings
	 * are unstable over our moving of them.
	 */
	ctl->syscall_ip = (unsigned long)ctl->remote_map + PATH_MAX;

	if (set_dgram_socket(ctl) < 0)
		goto destroy_parasite;

	*ret_ctl = ctl;
	return 0;

close_pagemap_fd:
	close(ctl->pagemap_fd);
err_free:
	free(ctl);
	return -1;

destroy_parasite:
	(void) destroy_parasite_ctl(pid, ctl);
	return -1;
}

int destroy_parasite_ctl(pid_t pid, struct parasite_ctl *ctl)
{
	unsigned long sret;
	int ret;

	close(ctl->pagemap_fd);
	destroy_dgram_socket(ctl);

	ctl->syscall_ip = ctl->syscall_ip_saved;
	ret = syscall_seized(ctl, __NR_munmap, &sret, (unsigned long)ctl->remote_map, ctl->map_length, 0, 0, 0, 0);
	if (ret || ((int)(long)sret) < 0) {
		pr_err("Can't munmap remote file\n");
		return ret ? ret : sret;
	}

	if (ctl->local_map != MAP_FAILED) {
		ret = munmap(ctl->local_map, ctl->map_length);
		if (ret) {
			pr_perror("Can't munmap local map");
			return -errno;
		}
	}
	free(ctl);
	return 0;
}

static int change_exe(struct parasite_ctl *ctl, int exe_fd)
{
	unsigned long sret;
	int ret;

	ret = syscall_seized(ctl, __NR_prctl, &sret, PR_SET_MM, PR_SET_MM_EXE_FILE, exe_fd, 0, 0, 0);
	if (ret < 0 || sret != 0) {
		pr_err("Can't set new exe pid=%d, ret=%d, sret=%d\n", ctl->pid, ret, (int)(long)sret);
		return -1;
	}

	ret = close_seized(ctl, exe_fd);
	if (ret < 0) {
		pr_err("Can't close temporary exe_fd=%d, pid=%d\n", exe_fd, ctl->pid);
		return -1;
	}

	return 0;
}

int swap_exe(struct parasite_ctl *ctl, int exe_fd)
{
	int ret, remote_fd;

	ret = remote_fd = transfer_local_fd(ctl, exe_fd);
	if (ret < 0)
		return ret;

	return change_exe(ctl, remote_fd);
}

static int change_cwd(struct parasite_ctl *ctl, int cwd_fd)
{
	int ret;

	ret = fchdir_seized(ctl, cwd_fd);
	if (ret < 0) {
		pr_err("Can't fchdir pid=%d\n", ctl->pid);
		return -1;
	}

	ret = close_seized(ctl, cwd_fd);
	if (ret < 0) {
		pr_err("Can't close temporary cwd_fd=%d, pid=%d\n", cwd_fd, ctl->pid);
		return -1;
	}

	return 0;
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
		pr_err("Can't create posix lock, pid=%d, ret=%d, sret=%d\n", ctl->pid, ret, ((int)(long)sret));
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
		pr_err("Wrong flock type\n");
		return -1;
	}

	ret = syscall_seized(ctl, __NR_flock, &sret, fd, type, 0, 0, 0, 0);
	if (ret < 0 || ((int)(long)sret) < 0) {
		pr_err("Can't create flock, pid=%d, ret=%d, sret=%d\n", ctl->pid, ret, ((int)(long)sret));
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
			pr_err("Can't parse fdinfo file\n");
			ret = -1;
			break;
		}
		p++;

		if (strncmp(p, " POSIX  ADVISORY  ", 18) == 0)
			is_posix = true;
		else if (strncmp(p, " FLOCK  ADVISORY  ", 18) == 0)
			is_posix = false;
		else {
			pr_err("Unknown lock type: %s", line);
			ret = -1;
			break;
		}
		p += 18;

		if (strncmp(p, "READ  ", 6) == 0)
			type = F_RDLCK;
		else if (strncmp(p, "WRITE ", 6) == 0)
			type = F_WRLCK;
		else {
			pr_err("Unknown lock type: %s", line);
			ret = -1;
			break;
		}
		p += 6;

		p = strrchr(p, ':');
		if (!p) {
			pr_err("Can't parse flock %s", line);
			ret = -1;
			break;
		}
		p++;

		if (sscanf(p, "%*d %ld %ld", &start, &end) == 1) {
			/* end is EOF */
			end = (loff_t)-1;
		}
		pr_debug("type=%u, start=%ld, end=%ld\n", type, start, end);

		new = malloc(sizeof(*new));
		if (!new) {
			pr_err("Can't do malloc()\n");
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
static int changefd(struct parasite_ctl *ctl, int src_fd, int dst_fd,
		    unsigned long f_setfd, long long f_pos)
{
	char fdinfo[] = "/proc/XXXXXXXXXX/fdinfo/XXXXXXXXXX";
	FILE *fp;
	unsigned long sret;
	int ret = 0, exit_code = 0;
	struct lock head = {.next = NULL,}, *ptr;

	sprintf(fdinfo, "/proc/%d/fdinfo/%d", ctl->pid, src_fd);
	fp = fopen(fdinfo, "r");
	if (!fp) {
		pr_perror("Can't open %s", fdinfo);
		exit_code = -1;
		goto out;
	}

	if (get_flocks(ctl, fp, &head) < 0) {
		exit_code = -1;
		goto out;
	}

	ret = syscall_seized(ctl, __NR_dup2, &sret, dst_fd, src_fd, 0, 0, 0, 0);
	if (ret < 0 || ((int)(long)sret) < 0) {
		pr_err("Can't dup2(%d, %d). pid=%d\n", dst_fd, src_fd, ctl->pid);
		exit_code = -1;
		goto out;
	}

	ret = close_seized(ctl, dst_fd);
	if (ret < 0) {
		pr_err("Can't close temporary fd, pid=%d\n", ctl->pid);
		exit_code = -1;
		goto out;
	}

	if (f_pos != 0) {
		ret = syscall_seized(ctl, __NR_lseek, &sret, src_fd, f_pos, SEEK_SET, 0, 0, 0);
		if (ret < 0 || ((int)(long)sret) < 0) {
			pr_err("Can't lseek pid=%d, fd=%d, ret=%d, sret=%d\n",
				ctl->pid, src_fd, ret, (int)(long)sret);
			exit_code = -1;
			goto out;
		}
	}

	ret = syscall_seized(ctl, __NR_fcntl, &sret, src_fd, F_SETFD, f_setfd, 0, 0, 0);
	if (ret < 0 || ((int)(long)sret) < 0) {
		pr_err("Can't fcntl pid=%d, fd=%d, ret=%d, sret=%d\n",
			ctl->pid, src_fd, ret, (int)(long)sret);
		exit_code = -1;
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

int swap_fd(struct parasite_ctl *ctl, int src_fd, int dst_fd,
	    unsigned long cloexec, long long pos)
{
	int err, remote_fd;

	remote_fd = transfer_local_fd(ctl, dst_fd);
	if (remote_fd < 0)
		return remote_fd;

	err = changefd(ctl, src_fd, remote_fd, cloexec, pos);
	if (err < 0)
		pr_err("failed to change source fd %d remote fd %d\n", src_fd, remote_fd);

	return err;
}

static int change_root(struct parasite_ctl *ctl, int cwd_fd, const char *root, bool restore_cwd)
{
	unsigned long sret;
	int old_cwd_fd, ret;

	if (cwd_fd == -1)
		restore_cwd = false;
	if (restore_cwd) {
		/* Save old cwd */
		strcpy(ctl->local_map, ".");
		ret = syscall_seized(ctl, __NR_open, &sret, (unsigned long)ctl->remote_map,
				     O_PATH, 0, 0, 0, 0);
		old_cwd_fd = (int)(long)sret;
		if (ret < 0 || old_cwd_fd < 0) {
			pr_err("Can't open: pid=%d ret=%d sret=%d\n", ctl->pid, ret, old_cwd_fd);
			return -1;
		}
	}

	if (cwd_fd != -1) {
		ret = fchdir_seized(ctl, cwd_fd);
		if (ret < 0) {
			pr_err("Can't fchdir to temporary cwd: pid=%d\n", ctl->pid);
			return -1;
		}
	}

	strcpy(ctl->local_map, root);
	ret = syscall_seized(ctl, __NR_chroot, &sret, (unsigned long)ctl->remote_map, 0, 0, 0, 0, 0);
	if (ret < 0 || sret != 0) {
		pr_err("Can't chroot, pid=%d, ret=%d, sret=%d\n", ctl->pid, ret, (int)(long)sret);
		return -1;
	}

	if (restore_cwd) {
		/* Restore old cwd */
		ret = fchdir_seized(ctl, old_cwd_fd);
		if (ret < 0) {
			pr_err("Can't restore old cwd: pid=%d\n", ctl->pid);
			return -1;
		}

		ret = close_seized(ctl, old_cwd_fd);
		if (ret < 0) {
			pr_err("Can't close old_cwd_fd=%d, pid=%d\n", old_cwd_fd, ctl->pid);
			return -1;
		}
	}

	if (cwd_fd != -1) {
		ret = close_seized(ctl, cwd_fd);
		if (ret < 0) {
			pr_err("Can't close cwd_fd=%d, pid=%d\n", cwd_fd, ctl->pid);
			return -1;
		}
	}

	return 0;
}

int swap_root(struct parasite_ctl *ctl, int cwd_fd, const char *root, bool restore_cwd)
{
	int ret, remote_fd = -1;

	if (cwd_fd >= 0) {
		ret = remote_fd = transfer_local_fd(ctl, cwd_fd);
		if (ret < 0)
			return ret;
	}

	return change_root(ctl, remote_fd, root, restore_cwd);
}

int swap_cwd(struct parasite_ctl *ctl, int cwd_fd)
{
	int ret, remote_fd;

	ret = remote_fd = transfer_local_fd(ctl, cwd_fd);
	if (ret < 0)
		return ret;

	return change_cwd(ctl, remote_fd);
}

static int seize_catch_task(pid_t pid)
{
	int ret;

	ret = ptrace(PTRACE_SEIZE, pid, NULL, 0);
	if (ret) {
		/* Error or task is exiting */
		pr_perror("Can't seize task %d", pid);
		return -1;
	}

	ret = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
	if (ret < 0) {
		/* Currently this happens only if task is exiting */
		pr_perror("Can't interrupt task %d", pid);

		if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
			pr_perror("Can't detach");
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
		pr_err("zombie found while seizing\n");
		return (pid_t)-1;
	}

	return pid;
}

int detach_from_task(pid_t pid, int orig_st)
{
	int status, ret;

	if (orig_st == TASK_STOPPED)
		kill(pid, SIGSTOP);

	ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (ret) {
		pr_perror("Can't detach from %d", pid);
		/* A process may be killed by SIGKILL */
		if (wait4(pid, &status, __WALL, NULL) == pid)
			ret = 0;
		else
			pr_perror("Unable to wait %d", pid);
	}

	return ret;

}

static int parse_pid_status(pid_t pid, struct proc_status_creds *cr)
{
	bool parsed_seccomp = false;
	char path[PATH_MAX];
	FILE *fp;
	int done = 0;
	int ret = -1;
	char *str = NULL;
	size_t len;

	sprintf(path, "/proc/%d/status", pid);

	fp = fopen(path, "r");
	if (!fp) {
		pr_perror("Can't open proc status");
		return -1;
	}

	cr->sigpnd = 0;
	cr->shdpnd = 0;

	while (done < 4 && getline(&str, &len, fp) > 0) {
		if (!strncmp(str, "State:", 6)) {
			cr->state = str[7];
			done++;
			continue;
		}

		if (!strncmp(str, "Seccomp:", 8)) {
			if (sscanf(str + 9, "%d", &cr->seccomp_mode) != 1) {
				goto err_parse;
			}

			parsed_seccomp = true;
			done++;
			continue;
		}

		if (!strncmp(str, "ShdPnd:", 7)) {
			unsigned long long sigpnd;

			if (sscanf(str + 7, "%llx", &sigpnd) != 1)
				goto err_parse;
			cr->shdpnd |= sigpnd;

			done++;
			continue;
		}
		if (!strncmp(str, "SigPnd:", 7)) {
			unsigned long long sigpnd;

			if (sscanf(str + 7, "%llx", &sigpnd) != 1)
				goto err_parse;
			cr->sigpnd |= sigpnd;

			done++;
			continue;
		}
	}

	if (done == 4 || (done == 3 && !parsed_seccomp))
		ret = 0;

err_parse:
	if (ret)
		pr_err("Error parsing proc status file: pid=%d\n", pid);
	free(str);
	fclose(fp);
	return ret;
}

static int skip_sigstop(int pid, int nr_signals)
{
	int i, status, ret;

	/*
	 * 1) SIGSTOP is queued, but isn't handled yet:
	 * SGISTOP can't be blocked, so we need to wait when the kernel
	 * handles this signal.
	 *
	 * Otherwise the process will be stopped immediatly after
	 * starting it.
	 *
	 * 2) A seized task was stopped:
	 * PTRACE_SEIZE doesn't affect signal or group stop state.
	 * Currently ptrace reported that task is in stopped state.
	 * We need to start task again, and it will be trapped
	 * immediately, because we sent PTRACE_INTERRUPT to it.
	 */
	for (i = 0; i < nr_signals; i++) {
		ret = ptrace(PTRACE_CONT, pid, 0, 0);
		if (ret) {
			pr_perror("Unable to start process");
			return -1;
		}

		ret = wait4(pid, &status, __WALL, NULL);
		if (ret < 0) {
			pr_perror("SEIZE %d: can't wait task", pid);
			return -1;
		}

		if (!WIFSTOPPED(status)) {
			pr_err("SEIZE %d: task not stopped after seize\n", pid);
			return -1;
		}
	}
	return 0;
}

/*
 * This routine seizes task putting it into a special
 * state where we can manipulate the task via ptrace
 * interface, and finally we can detach ptrace out of
 * of it so the task would not know if it was saddled
 * up with someone else.
 */
int wait_task_seized(pid_t pid)
{
	siginfo_t si;
	int status, nr_sigstop;
	int ret = 0, ret2, wait_errno = 0;
	struct proc_status_creds cr;

	/*
	 * For the comparison below, let's zero out any padding.
	 */
	memset(&cr, 0, sizeof(struct proc_status_creds));

try_again:

	ret = wait4(pid, &status, __WALL, NULL);
	if (ret < 0) {
		/*
		 * wait4() can expectedly fail only in a first time
		 * if a task is zombie. If we are here from try_again,
		 * this means that we are tracing this task.
		 *
		 * processes_to_wait should be descrimented only once in this
		 * function if a first wait was success.
		 */
		wait_errno = errno;
	}

	ret2 = parse_pid_status(pid, &cr);
	if (ret2)
		goto err;

	if (ret < 0 || WIFEXITED(status) || WIFSIGNALED(status)) {
		if (cr.state != 'Z') {
			if (pid == getpid())
				pr_err("The criu itself is within dumped tree.\n");
			else
				pr_err("Unseizable non-zombie %d found, state %c, err %d/%d\n",
						pid, cr.state, ret, wait_errno);
			return -1;
		}

		return TASK_DEAD;
	}

	if (!WIFSTOPPED(status)) {
		pr_err("SEIZE %d: task not stopped after seize\n", pid);
		goto err;
	}

	ret = ptrace(PTRACE_GETSIGINFO, pid, NULL, &si);
	if (ret < 0) {
		pr_perror("SEIZE %d: can't read signfo", pid);
		goto err;
	}

	if (SI_EVENT(si.si_code) != PTRACE_EVENT_STOP) {
		/*
		 * Kernel notifies us about the task being seized received some
		 * event other than the STOP, i.e. -- a signal. Let the task
		 * handle one and repeat.
		 */

		if (ptrace(PTRACE_CONT, pid, NULL,
					(void *)(unsigned long)si.si_signo)) {
			pr_perror("Can't continue signal handling, aborting");
			goto err;
		}

		ret = 0;
		goto try_again;
	}

	if (cr.seccomp_mode != SECCOMP_MODE_DISABLED && suspend_seccomp(pid) < 0)
		goto err;

	nr_sigstop = 0;
	if (cr.sigpnd & (1 << (SIGSTOP - 1)))
		nr_sigstop++;
	if (cr.shdpnd & (1 << (SIGSTOP - 1)))
		nr_sigstop++;
	if (si.si_signo == SIGSTOP)
		nr_sigstop++;

	if (nr_sigstop) {
		if (skip_sigstop(pid, nr_sigstop))
			goto err_stop;

		return TASK_STOPPED;
	}

	if (si.si_signo == SIGTRAP)
		return TASK_ALIVE;
	else {
		pr_err("SEIZE %d: unsupported stop signal %d\n", pid, si.si_signo);
		goto err;
	}

err_stop:
	kill(pid, SIGSTOP);
err:
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
		pr_perror("Unable to detach from %d", pid);
	return -1;
}

