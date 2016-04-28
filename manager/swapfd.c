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
#include "include/log.h"

#include "swapfd.h"

#define MMAP_SIZE PATH_MAX

static int wait_task_seized(pid_t pid)
{
	int status, ret;

	ret = wait4(pid, &status, __WALL, NULL);
	if (ret < 0) {
		pr_perror("Can't wait %d", pid);
		return ret;
	}

	if (WIFEXITED(status) || WIFSIGNALED(status))
		return -1;

	if (!WIFSTOPPED(status)) {
		pr_err("SEIZE %d: task not stopped after seize\n", pid);
		return -1;
	}

	return 0;
}

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
		pr_perror("Can't open %s", path);
		return result;
	}

	while (getline(&line, &size, fp) != -1) {
		unsigned long start, end;
		char r, w, x;
		int ret;

		ret = sscanf(line, "%lx%*c%lx %c%c%c", &start, &end, &r, &w, &x);
		if (ret != 5) {
			pr_perror("Can't parse line: %s", line);
			continue;
		}

		if (x != 'x')
			continue;

		pr_debug("Found: start=%08lx, end=%08lx, r=%c, w=%c, x=%c\n",
				start, end, r, w, x);
		result = (void *)start;
		break;
	}

	free(line);
	fclose(fp);

	return result;
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

	*ret_ctl = ctl;
	pr_debug("Set up parasite blob using memfd\n");
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

	ret = syscall_seized(ctl, __NR_munmap, &sret, (unsigned long)ctl->remote_map, ctl->map_length, 0, 0, 0, 0);
	if (ret || ((int)(long)sret) < 0)
		pr_err("Can't munmap remote file\n");

	ret = munmap(ctl->local_map, ctl->map_length);
	if (ret)
		pr_perror("Can't munmap local map");
}

static int get_fd_mode(FILE *fp, long long int *pos, mode_t *mode)
{
	int i = 0;
	char *line = NULL;
	size_t size = 0;

	while (getline(&line, &size, fp) != -1) {
		if (strncmp(line, "pos:\t", 5) == 0)
			sscanf(line + 5, "%lli", pos);
		else if (strncmp(line, "flags:\t0", 8) == 0)
			sscanf(line + 8, "%o", mode);
		else {
			pr_err("Can't parse fdinfo file\n");
			return -1;
		}
		if (++i == 2)
			break;
	}
	pr_debug("pos=%lli, mode=0%o\n", *pos, *mode);
	free(line);
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

	pr_debug("make posix lock: ret=%d, sret=%lu\n", ret, sret);

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

static int changefd(struct parasite_ctl *ctl, pid_t pid, int src_fd, const char *dst_path)
{
	char fdinfo[] = "/proc/XXXXXXXXXX/fdinfo/XXXXXXXXXX";
	FILE *fp;
	long long int f_pos;
	unsigned long sret;
	mode_t mode;
	int new_fd, ret, exit_code = 0;
	struct lock l, *head = &l;

	sprintf(fdinfo, "/proc/%d/fdinfo/%d", pid, src_fd);
	fp = fopen(fdinfo, "r");
	if (!fp) {
		pr_perror("Can't open %s", fdinfo);
		return -EIO;
	}

	head->next = NULL;
	if (get_fd_mode(fp, &f_pos, &mode) < 0) {
		exit_code = -1;
		goto out;
	}

	strcpy((char *)ctl->local_map, dst_path);

	ret = syscall_seized(ctl, __NR_open, &sret, (unsigned long)ctl->remote_map, mode, 0, 0, 0, 0);
	new_fd = (int)(long)sret;
	if (ret < 0 || new_fd < 0) {
		pr_err("Can't open dst file %s, new_fd=%d\n", dst_path, new_fd);
		exit_code = -1;
		goto out;
	}

	if (get_flocks(ctl, fp, head) < 0) {
		exit_code = -1;
		goto out;
	}

	ret = syscall_seized(ctl, __NR_dup2, &sret, new_fd, src_fd, 0, 0, 0, 0);
	if (ret < 0 || ((int)(long)sret) < 0) {
		pr_err("Can't dup2(). pid=%d, dst_path=%s\n", pid, dst_path);
		exit_code = -1;
	}

	ret = syscall_seized(ctl, __NR_close, &sret, new_fd, 0, 0, 0, 0, 0);
	if (ret < 0 || sret != 0) {
		pr_err("Can't close temporary fd, pid=%d\n", pid);
		exit_code = -1;
	}

	if (exit_code == 0) {
		ret = syscall_seized(ctl, __NR_lseek, &sret, src_fd, f_pos, SEEK_SET, 0, 0, 0);
		if (ret < 0 || ((int)(long)sret) < 0) {
			pr_err("Can't lseek in %s, pid=%d\n", dst_path, pid);
			exit_code = -1;
		}
	}
out:
	head = head->next;
	while (head) {
		struct lock *prev = head;
		if (exit_code == 0) {
			if (head->is_posix)
				ret = make_posix_lock(ctl, src_fd, head->type, head->start, head->end);
			else
				ret = make_flock_lock(ctl, src_fd, head->type);
		}
		if (ret)
			exit_code = ret;
		head = head->next;
		free(prev);
	}

	fclose(fp);
	return exit_code;
}

static int swapfd_tracee(pid_t pid, bool (*match_fn) (pid_t pid, int fd, char *path, void *data),
	   void (*dst_name_fn) (pid_t pid, char *name, void *data), void *data)
{
	char dpath[PATH_MAX], link[PATH_MAX], path[PATH_MAX];
	struct parasite_ctl *ctl = NULL;
	struct dirent *dt;
	DIR *dir;
	int ret = 0;

	snprintf(dpath, PATH_MAX, "/proc/%d/fd", pid);
	dir = opendir(dpath);
	if (!dir) {
		pr_perror("opendir()");
		return -1;
	}

	errno = 0;
	while ((dt = readdir(dir)) != NULL) {
		int cur_fd;
		if (!strcmp(dt->d_name, ".") ||
		    !strcmp(dt->d_name, ".."))
			continue;

		snprintf(link, PATH_MAX, "%s/%s", dpath, dt->d_name);

		ret = readlink(link, path, PATH_MAX);
		if (ret == -1) {
			pr_perror("Can't readlink");
			goto closedir;
		}
		path[ret] = '\0';
		ret = 0;

		cur_fd = atoi(dt->d_name);
		if (!match_fn(pid, cur_fd, path, data))
			continue;

		if (!ctl) {
			/*
			 * We create parasite after match_fn to do that
			 * only when it's really need.
			 */
			ret = set_parasite_ctl(pid, &ctl);
			if (ret < 0)
				goto closedir;
		}

		pr_debug("matched: %s, ", path);
		dst_name_fn(pid, path, data);
		pr_debug("opening: %s\n", path);

		ret = changefd(ctl, pid, cur_fd, path);
		if (ret < 0)
			goto closedir;
	}

	if (errno) {
		pr_perror("readdir()");
		ret = errno;
	}

closedir:
	closedir(dir);
	if (ctl)
		destroy_parasite_ctl(pid, ctl);

	return ret;
}

int swapfd(pid_t pid, bool (*match_fn) (pid_t pid, int fd, char *path, void *data),
	   void (*dst_name_fn) (pid_t pid, char *name, void *data), void *data)
{
	int ret, err;
	bool interrupted;

	err = ptrace(PTRACE_SEIZE, pid, NULL, 0);
	if (err) {
		/* Error or task is exiting */
		pr_err("Can't seize task %d\n", pid);
		return -1;
	}

	interrupted = !ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
	if (!interrupted) {
		/* Currently this happens only if task is exiting */
		pr_err("Can't interrupt task %d\n", pid);
	}

	err = wait_task_seized(pid);

	if (!interrupted || err) {
		ret = err;
		goto detach;
	}

	err = swapfd_tracee(pid, match_fn, dst_name_fn, data);
	if (err) {
		ret = err;
		goto detach;
	}

	ret = 0;
detach:
	err = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (err) {
		pr_perror("Can't detach");
		ret = err;
	}

	return ret;
}
