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
#include "processes.h"
#include "fd_tree.h"
#include "swapfd.h"

#if 0
struct fifo_data {
	struct list_head list;
	char path[PATH_MAX];
	int read_fd;
	int write_fd;
	bool loaded;
};

static struct fifo_data *create_fifo_data(const char *path)
{
	struct fifo_data *fifo;

	fifo = malloc(sizeof(*fifo));
	if (!fifo) {
		pr_err("failed to allocate\n");
		return NULL;
	}

	fifo->read_fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fifo->read_fd == -1) {
		pr_perror("failed to open %s in read mode", path);
		goto free_fifo;
	}

	fifo->write_fd = open(path, O_WRONLY | O_NONBLOCK);
	if (fifo->write_fd == -1) {
		pr_perror("failed to open %s in write mode", path);
		goto close_read_fd;
	}

	fifo->loaded = false;
	pr_debug("created new fifo object for %s\n", path);
	return fifo;

close_read_fd:
	close(fifo->read_fd);
free_fifo:
	free(fifo);
	return NULL;
}

static int do_fifo_magic(struct spfs_info_s *info,
		     const char *path, const char *fd_path)
{
	static LIST_HEAD(fifos);
	struct fifo_data *fifo = NULL, *tmp;

	list_for_each_entry(tmp, &fifos, list) {
		if (!strcmp(tmp->path, path)) {
			fifo = tmp;
			break;
		}
	}

	if (!fifo) {
		fifo = create_fifo_data(path);
		if (!fifo) {
			pr_err("failed to create fifo object\n");
			return -EPERM;
		}
	}

	if (!fifo->loaded) {
		int fd;
		ssize_t bytes;

		fd = open(fd_path, O_RDONLY | O_NONBLOCK);
		if (fd == -1) {
			pr_perror("failed to open %s", fd_path);
			return -errno;
		}

		bytes = fcntl(fd, F_GETPIPE_SZ);
		if (bytes < 0) {
			pr_perror("failed to discover %s capacity", fd_path);
			close(fd);
			return -1;
		}

		pr_debug("%s capacity: %ld\n", path, bytes);

		bytes = tee(fd, fifo->write_fd, bytes, SPLICE_F_NONBLOCK);
		if (bytes < 0) {
			pr_perror("failed to splice data from %s to %s", fd_path, path);
			close(fd);
			return -1;
		}
		close(fd);
		pr_debug("Copied %ld bytes to fifo object %s\n", bytes, path);
	}
	return 0;
}

static int do_file_magic(struct spfs_info_s *info,
			 const char *path, const char *fd_path)
{
	char full_path[PATH_MAX];
	struct stat st;

	snprintf(full_path, PATH_MAX, "%s/%s", info->mountpoint, path);
	if (stat(full_path, &st)) {
		pr_perror("failed to stat %s");
		return -errno;
	}

	switch (st.st_mode & S_IFMT) {
		case S_IFIFO:
			return do_fifo_magic(info, full_path, fd_path);
		case S_IFSOCK:
		case S_IFLNK:
		case S_IFREG:
		case S_IFBLK:
		case S_IFDIR:
		case S_IFCHR:
			break;
		default:
			pr_err("unknows file mode: 0%o\n", st.st_mode & S_IFMT);
			return -EINVAL;
	}
	return 0;
}

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

	if (do_file_magic(info, path, fd_path))
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
#endif

static int do_swap_process_resources(struct process_info *p)
{
	struct process_fd *pfd;
	struct process_map *mfd;
	int *src_fd, *dst_fd, *s, *d;
	int *map_fd, *m;
	unsigned long *map_addr, *ma;
	int err = -ENOMEM;

	pr_debug("Replacing process %d resources (%d)\n", p->pid, p->fds_nr);

	src_fd = malloc(sizeof(int) * p->fds_nr);
	dst_fd = malloc(sizeof(int) * p->fds_nr);
	map_fd = malloc(sizeof(int) * p->maps_nr);
	map_addr = malloc(sizeof(long) * p->maps_nr);
	if (!src_fd || !dst_fd ||
	    !map_fd || !map_addr)
		goto free;

	s = src_fd;
	d = dst_fd;

	list_for_each_entry(pfd, &p->fds, list) {
		pr_debug("/proc/%d/fd/%d --> /proc/%d/fd/%d\n",
				getpid(), pfd->real_fd, p->pid, pfd->spfs_fd);
		*s++ = pfd->spfs_fd;
		*d++ = pfd->real_fd;
	}

	m = map_fd;
	ma = map_addr;

	list_for_each_entry(mfd, &p->maps, list) {
		pr_debug("/proc/%d/fd/%d --> /proc/%d/map_files/%ld-%ld\n",
				getpid(), mfd->map_fd, p->pid, mfd->start, mfd->end);
		*m++ = mfd->map_fd;
		*ma++ = mfd->start;
	}

	if (p->env.exe_fd >= 0)
		pr_debug("/proc/%d/fd/%d --> /proc/%d/exe\n",
				getpid(), p->env.exe_fd, p->pid);

	if (p->env.cwd_fd >= 0)
		pr_debug("/proc/%d/fd/%d --> /proc/%d/cwd\n",
				getpid(), p->env.cwd_fd, p->pid);
	if (p->env.root_fd >= 0)
		pr_debug("/proc/%d/fd/%d --> /proc/%d/root\n",
				getpid(), p->env.root_fd, p->pid);

	err = swapfd_tracee(p->pid, map_addr, map_fd, p->maps_nr,
			    src_fd, dst_fd, p->fds_nr);

free:
	free(src_fd);
	free(dst_fd);
	free(map_fd);
	free(map_addr);
	return err;
}

int do_swap_resources(struct spfs_info_s *info)
{
	struct process_info *p;

	list_for_each_entry(p, &info->processes, list) {
		if (do_swap_process_resources(p))
			pr_err("failed to swap resources for process %d\n", p->pid);
	}

	return 0;
}
