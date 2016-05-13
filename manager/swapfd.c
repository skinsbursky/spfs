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

struct map_struct {
	struct list_head list;
	unsigned long start, end, ino;
	unsigned long long pgoff;
	unsigned major, minor;
	char r, w, x, s;
	int moved;
};

static int collect_map(struct parasite_ctl *ctl, struct map_struct *m)
{
	struct map_struct *new = malloc(sizeof(*new));

	if (!new) {
		pr_perror("Can't alloc map_struct");
		return -1;
	}

	memcpy(new, m, sizeof(*m));
	new->moved = 0;
	list_add_tail(&new->list, &ctl->maps);

	return 0;
}

static void *find_mapping(pid_t pid, struct parasite_ctl *ctl)
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
		struct map_struct m;
		int ret;

		ret = sscanf(line, "%lx%*c%lx %c%c%c%c %llx %x%*c%x %lu",
			     &m.start, &m.end, &m.r, &m.w, &m.x, &m.s,
			     &m.pgoff, &m.major, &m.minor, &m.ino);
		if (ret != 10) {
			pr_err("Can't parse line: %s", line);
			result = MAP_FAILED;
			break;
		}

		if (m.ino && collect_map(ctl, &m) < 0) {
			result = MAP_FAILED;
			break;
		}

		if (m.x != 'x' || m.start > TASK_SIZE)
			continue;

		pr_debug("Found: start=%08lx, end=%08lx, r=%c, w=%c, x=%c\n",
				m.start, m.end, m.r, m.w, m.x);
		result = (void *)m.start;
	}

	free(line);
	fclose(fp);

	if (result == MAP_FAILED) {
		struct map_struct *m, *tmp;
		list_for_each_entry_safe(m, tmp, &ctl->maps, list) {
			free(m);
		}
	}

	return result;
}

static void free_mappings(struct parasite_ctl *ctl)
{
	struct map_struct *m, *tmp;
	list_for_each_entry_safe(m, tmp, &ctl->maps, list)
		free(m);
}

static int copy_private_content(struct parasite_ctl *ctl, unsigned long to,
				unsigned long from, unsigned long size)
{
	char path[] = "/proc/XXXXXXXXXX/mem";
	int src, dst, ret = -1;
	size_t copied;
	off_t off;

	sprintf(path, "/proc/%d/mem", ctl->pid);
	src = open(path, O_RDONLY);
	dst = open(path, O_WRONLY);
	if (src < 0 || dst < 0) {
		pr_perror("Can't open %s: %d %d\n", path, src, dst);
		goto out;
	}

	off = lseek(dst, to, SEEK_SET);
	if (off == (off_t) -1) {
		pr_perror("Can't lseek in %s on %lx", path, to);
		goto out;
	}

	off = lseek(src, from, SEEK_SET);
	if (off == (off_t) -1) {
		pr_perror("Can't lseek in %s on %lx", path, from);
		goto out;
	}

	copied = sendfile(dst, src, NULL, size);
	if (copied < 0) {
		pr_perror("Can't sendfile: pid=%d, from=%lx, to=%lx, size=%lx",
			  ctl->pid, from, to, size);
		goto out;
	}

	ret = 0;
out:
	close(src);
	close(dst);
	return ret;
}

/* Find mapping backed by src_fd OR starting at src_addr and make them backed by dst_fd */
static int move_mappings(struct parasite_ctl *ctl, unsigned long src_addr, int src_fd, int dst_fd)
{
	unsigned int dev_major = 0, dev_minor = 0;
	int ret, prot, flags, moved = 0;
	unsigned long sret, addr;
	struct map_struct *map;
	char path[PATH_MAX];
	struct stat st;
	size_t length;

	if (src_fd >= 0) {
		sprintf(path, "/proc/%d/fd/%d", ctl->pid, src_fd);

		if (stat(path, &st) < 0) {
			pr_perror("Can't do stat on %s", path);
			return -1;
		}

		dev_major = major(st.st_dev);
		dev_minor = minor(st.st_dev);
	}

	list_for_each_entry(map, &ctl->maps, list) {
		if (map->moved)
			continue;
		if (src_fd >= 0) {
			if (map->major != dev_major || map->minor != dev_minor ||
			    map->ino != st.st_ino)
				continue;
		} else {
			if (map->start != src_addr)
				continue;
		}

		length = map->end - map->start;

		ret = syscall_seized(ctl, __NR_msync, &sret, map->start, length, MS_SYNC, 0, 0, 0);
		if (ret || sret) {
			pr_err("Can't msync at [%lx; %lx], ret=%d, sret=%d\n",
				map->start, map->end, ret, (int)(long)sret);
			return -1;
		}

		prot = 0;
		if (map->r == 'r')
			prot |= PROT_READ;
		if (map->w == 'w')
			prot |= PROT_WRITE;
		if (map->x == 'x')
			prot |= PROT_EXEC;

		flags = map->s == 's' ? MAP_SHARED : MAP_PRIVATE;

		pr_debug("mmap to replace %lx: len=%lx, prot=%x, flags=%x, off=%lx\n",
			 map->start, length, prot, flags, map->pgoff);
		ret = syscall_seized(ctl, __NR_mmap, &sret, 0, length, prot, flags, dst_fd, map->pgoff);
		if (ret || IS_ERR_VALUE(sret)) {
			pr_err("Can't mmap: ret=%d, sret=%d\n", ret, (int)(long)sret);
			return -1;
		}
		addr = sret;

		if (flags & MAP_PRIVATE) {
			ret = copy_private_content(ctl, addr, map->start, length);
			if (ret)
				return -1;
		}

		flags = MREMAP_FIXED | MREMAP_MAYMOVE;
		pr_debug("remapping %lx to %lx, size=%lx\n", addr, map->start, length);
		ret = syscall_seized(ctl, __NR_mremap, &sret, addr, length, length, flags, map->start, 0);
		if (ret || IS_ERR_VALUE(sret)) {
			pr_err("Can't remap: ret=%d, sret=%d\n", ret, (int)(long)sret);
			return -1;
		}

		moved = map->moved = 1;
	}

	if (src_fd < 0 && !moved) {
		pr_err("Can't find a mapping with addr=%lx\n", src_addr);
		return -1;
	}

	return 0;
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
		pr_err("Can't destroy dgram socket\n");
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
		pr_err("Can't create dgram socket: %d %d", ret, fd);
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
			pr_err("Can't bind: %d %d\n", ret, err);
			break;
		}

		ctl->local_sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (ctl->local_sockfd < 0) {
			pr_perror("Can't create local sock", errno);
			break;
		}

		memcpy(&ctl->addr, addr, sizeof(*addr));
		ctl->addrlen = len + len2 + sizeof(addr->sun_family);
		pr_debug("Set socket %s\n", addr->sun_path);

		return 0;
	}

	pr_err("Can't set dgram sockets\n");
	destroy_dgram_socket(ctl);
	return -1;
}

static int set_parasite_ctl(pid_t pid, struct parasite_ctl **ret_ctl)
{
	char path[] = "/proc/XXXXXXXXXX/fd/XXXXXXXXXX";
	void *addr, *where;
	uint8_t orig_code[] = "SWAPMFD";
	unsigned long sret = -ENOSYS;
	struct parasite_ctl *ctl;
	int ret, fd, lfd;

	ctl = malloc(sizeof(*ctl));
	if (!ctl) {
		pr_err("Can't alloc ctl\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&ctl->maps);

	addr = find_mapping(pid, ctl);
	where = addr + BUILTIN_SYSCALL_SIZE;

	if (addr == MAP_FAILED) {
		pr_err("Can't find a useful mapping, pid=%d\n", pid);
		return -ENOMEM;
	}

	ctl->pid = pid;
	ctl->syscall_ip = (unsigned long)addr;
	ctl->syscall_ip_saved = (unsigned long)addr;
	ctl->remote_sockfd = -1;
	ctl->local_sockfd = -1;

        if (get_thread_ctx(pid, &ctl->orig))
		goto err_free;

	if (ptrace_swap_area(pid, where, (void *)orig_code, sizeof(orig_code))) {
		pr_err("Can't inject memfd args (pid: %d)\n", pid);
		goto err_free;
	}

	ret = syscall_seized(ctl, __NR_memfd_create, &sret,
			     (unsigned long)where, 0, 0, 0, 0, 0);

	if (ptrace_poke_area(pid, orig_code, where, sizeof(orig_code))) {
		fd = (int)(long)sret;
		if (fd >= 0)
			syscall_seized(ctl, __NR_close, &sret, fd, 0, 0, 0, 0, 0);
		pr_err("Can't restore memfd args (pid: %d)\n", pid);
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
		pr_perror("Can't open %s", path);
		goto err_cure;
	}

	if (ftruncate(lfd, ctl->map_length) < 0) {
		pr_perror("Fail to truncate memfd for parasite");
		goto err_cure;
	}

	ctl->remote_map = mmap_seized(ctl, NULL, MMAP_SIZE,
				      PROT_READ | PROT_WRITE | PROT_EXEC,
				      MAP_FILE | MAP_SHARED, fd, 0);
	if (!ctl->remote_map) {
		pr_err("Can't rmap memfd for parasite blob\n");
		goto err_curef;
	}

	ctl->local_map = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_FILE, lfd, 0);
	if (ctl->local_map == MAP_FAILED) {
		pr_perror("Can't lmap memfd for parasite blob");
		goto err_curef;
	}

	syscall_seized(ctl, __NR_close, &sret, fd, 0, 0, 0, 0, 0);
	close(lfd);
	/*
	 * Use allocated memory for syscall number, because task's mappings
	 * are unstable over our moving of them.
	 */
	ctl->syscall_ip = (unsigned long)ctl->remote_map + PATH_MAX;

	if (set_dgram_socket(ctl) < 0) {
		destroy_parasite_ctl(pid, ctl);
		goto err_free;
	}

	*ret_ctl = ctl;
	pr_debug("Set up parasite blob using memfd\n");
	return 0;

err_curef:
	close(lfd);
err_cure:
	syscall_seized(ctl, __NR_close, &sret, fd, 0, 0, 0, 0, 0);
err_free:
	free_mappings(ctl);
	free(ctl);
	return -1;
}

static void destroy_parasite_ctl(pid_t pid, struct parasite_ctl *ctl)
{
	unsigned long sret;
	int ret;

	destroy_dgram_socket(ctl);

	ctl->syscall_ip = ctl->syscall_ip_saved;
	ret = syscall_seized(ctl, __NR_munmap, &sret, (unsigned long)ctl->remote_map, ctl->map_length, 0, 0, 0, 0);
	if (ret || ((int)(long)sret) < 0)
		pr_err("Can't munmap remote file\n");

	ret = munmap(ctl->local_map, ctl->map_length);
	if (ret)
		pr_perror("Can't munmap local map");
	free_mappings(ctl);
	free(ctl);
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
			pr_err("Can't parse fdinfo file\n");
			ret = -1;
			break;
		}
		if (++i == 2)
			break;
	}
	pr_debug("pos=%lli, mode=0%o\n", *pos, *mode);
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

static int send_dst_fd(struct parasite_ctl *ctl, int fd)
{
	return send_fd(ctl->local_sockfd, &ctl->addr, ctl->addrlen, fd);
}

/* Receive next fd from receive queue of remote_sockfd */
static int get_next_fd(struct parasite_ctl *ctl)
{
	return recv_fd(ctl);
}

static int change_exe(struct parasite_ctl *ctl)
{
	unsigned long sret;
	int exe_fd, ret;

	exe_fd = get_next_fd(ctl);
	if (exe_fd < 0) {
		pr_err("Can't receive exe fd\n");
		return -1;
	}

	ret = syscall_seized(ctl, __NR_prctl, &sret, PR_SET_MM, PR_SET_MM_EXE_FILE, exe_fd, 0, 0, 0);
	if (ret < 0 || sret != 0) {
		pr_err("Can't set new exe pid=%d, ret=%d, sret=%d\n", ctl->pid, ret, (int)(long)sret);
		return -1;
	}

	ret = syscall_seized(ctl, __NR_close, &sret, exe_fd, 0, 0, 0, 0, 0);
	if (ret < 0 || sret != 0) {
		pr_err("Can't close temporary exe_fd=%d, pid=%d\n", exe_fd, ctl->pid);
		return -1;
	}

	return 0;
}

static int changemap(struct parasite_ctl *ctl, unsigned long addr)
{
	int fd = get_next_fd(ctl);
	unsigned long sret;
	int ret;

	if (fd < 0) {
		pr_err("Can't receive new fd\n");
		return -1;
	}
	pr_debug("Received fd=%d\n", fd);

	if (move_mappings(ctl, addr, -1, fd) < 0) {
		pr_err("Can't move mapping on addr %lx\n", addr);
		return -1;
	}

	ret = syscall_seized(ctl, __NR_close, &sret, fd, 0, 0, 0, 0, 0);
	if (ret < 0 || sret != 0) {
		pr_err("Can't close temporary fd=%d, pid=%d\n", fd, ctl->pid);
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
static int changefd(struct parasite_ctl *ctl, pid_t pid, int src_fd, int dst_fd)
{
	char fdinfo[] = "/proc/XXXXXXXXXX/fdinfo/XXXXXXXXXX";
	FILE *fp;
	long long int f_pos;
	unsigned long sret;
	mode_t mode;
	int new_fd, ret = 0, exit_code = 0;
	struct lock head = {.next = NULL,}, *ptr;
	bool need_lseek;
	struct stat st;

	if (fstat(dst_fd, &st) < 0) {
		pr_perror("Can't stat on dst_fd");
		return -1;
	}
	need_lseek = (st.st_mode & (S_IFREG | S_IFBLK | S_IFDIR)) != 0;

	sprintf(fdinfo, "/proc/%d/fdinfo/%d", pid, src_fd);
	fp = fopen(fdinfo, "r");
	if (!fp) {
		pr_perror("Can't open %s", fdinfo);
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
		pr_err("Can't receive fd\n");
		exit_code = -1;
		goto out;
	}

	pr_debug("Received fd=%d\n", new_fd);

	if (move_mappings(ctl, ~0UL, src_fd, new_fd) < 0)
		return -1;

	ret = syscall_seized(ctl, __NR_dup2, &sret, new_fd, src_fd, 0, 0, 0, 0);
	if (ret < 0 || ((int)(long)sret) < 0) {
		pr_err("Can't dup2(%d, %d). pid=%d\n", new_fd, src_fd, pid);
		exit_code = -1;
	}

	ret = syscall_seized(ctl, __NR_close, &sret, new_fd, 0, 0, 0, 0, 0);
	if (ret < 0 || sret != 0) {
		pr_err("Can't close temporary fd, pid=%d\n", pid);
		exit_code = -1;
	}

	if (exit_code == 0 && need_lseek) {
		ret = syscall_seized(ctl, __NR_lseek, &sret, src_fd, f_pos, SEEK_SET, 0, 0, 0);
		if (ret < 0 || ((int)(long)sret) < 0) {
			pr_err("Can't lseek pid=%d, fd=%d, ret=%d, sret=%d\n",
				pid, src_fd, ret, (int)(long)sret);
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

int swapfd_tracee(struct swapfd_exchange *se)
{
	struct parasite_ctl *ctl;
	int i, ret;

	ret = set_parasite_ctl(se->pid, &ctl);
	if (ret < 0)
		goto out_close;

	for (i = 0; i < se->naddr; i++) {
		ret = send_dst_fd(ctl, se->addr_fd[i]);
		if (ret < 0)
			goto out_destroy;

		ret = changemap(ctl, se->addr[i]);
		if (ret < 0)
			goto out_destroy;
	}

	for (i = 0; i < se->nfd; i++) {
		ret = send_dst_fd(ctl, se->dst_fd[i]);
		if (ret)
			goto out_destroy;
		ret = changefd(ctl, se->pid, se->src_fd[i], se->dst_fd[i]);
		if (ret < 0)
			goto out_destroy;
	}

	if (se->exe_fd >= 0) {
		ret = send_dst_fd(ctl, se->exe_fd);
		if (ret < 0)
			goto out_destroy;

		ret = change_exe(ctl);
		if (ret < 0)
			goto out_destroy;
	}

out_destroy:
	destroy_parasite_ctl(se->pid, ctl);
out_close:
	close_fds(se->dst_fd, se->naddr + se->nfd);
	return ret;
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

int detach_from_task(pid_t pid)
{
	int status, ret;

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

int wait_task_seized(pid_t pid)
{
	int status, ret;
	siginfo_t si;

try_again:
	ret = wait4(pid, &status, __WALL, NULL);
	if (ret < 0) {
		pr_perror("Can't wait %d", pid);
		return ret;
	}

	if (WIFEXITED(status) || WIFSIGNALED(status)) {
		pr_err("Task exited unexpected %d\n", pid);
		return -1;
	}

	if (!WIFSTOPPED(status)) {
		pr_err("SEIZE %d: task not stopped after seize\n", pid);
		return -1;
	}

	ret = ptrace(PTRACE_GETSIGINFO, pid, NULL, &si);
	if (ret < 0) {
		pr_perror("SEIZE %d: can't read signfo", pid);
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
			pr_perror("Can't continue signal handling, aborting, pid=%d, errno=%d", pid, errno);
			return -1;
		}

		ret = 0;
		goto try_again;
	}

	return 0;
}
