#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "include/list.h"
#include "include/log.h"
#include "include/util.h"
#include "include/shm.h"
#include "include/namespaces.h"
#include "include/pie-util-fd.h"

#include "spfs.h"
#include "trees.h"
#include "swapfd.h"
#include "processes.h"
#include "file_obj.h"
#include "swapfd.h"

struct mounts_info_s {
	dev_t			src_dev;
	const char		*source_mnt;
	const char		*target_mnt;
};

struct fd_info_s {
	int             fd;
	struct stat     st;
	unsigned        flags;
	long long	pos;
	char            path[PATH_MAX];
};

static int seize_one_process(struct process_info *p)
{
	p->orig_st = wait_task_seized(p->pid);
	if (p->orig_st < 0) {
		pr_err("failed to seize process %d\n", p->pid);
		return -EPERM;
	}
	pr_debug("\t%d seized\n", p->pid);

	return set_parasite_ctl(p->pid, &p->pctl);
}

int seize_processes(struct list_head *processes)
{
	struct process_info *p;

	pr_debug("Seizing processes...\n");

	list_for_each_entry(p, processes, list) {
		if (seize_one_process(p))
			return -EPERM;
	}
	return 0;
}

static int detach_from_process(const struct process_info *p)
{
	if (detach_from_task(p->pid, p->orig_st)) {
		pr_err("failed to detach from process %d\n", p->pid);
		return -EPERM;
	}
	pr_debug("detached from process %d\n", p->pid);
	return 0;
}

static int destroy_process_maps(struct process_info *p)
{
	struct process_map *mfd, *tmp;

	if (!p->maps_nr)
		return 0;

	list_for_each_entry_safe(mfd, tmp, &p->maps, list) {
		list_del(&mfd->list);
		free(mfd);
	}

	return 0;
}

static int destroy_process_fds(struct process_info *p)
{
	struct process_fd *pfd, *tmp;

	if (!p->fds_nr)
		return 0;

	list_for_each_entry_safe(pfd, tmp, &p->fds, list) {
		list_del(&pfd->list);
		free(pfd);
	}

	return 0;
}

static void destroy_one_process(struct process_info *p)
{
	destroy_process_maps(p);
	destroy_process_fds(p);
	list_del(&p->list);
	free(p);
}

static void release_one_process(struct process_info *p)
{
	if (p->pctl)
		(void) destroy_parasite_ctl(p->pid, p->pctl);
	(void) detach_from_process(p);
}

int release_processes(struct list_head *processes)
{
	struct process_info *p, *tmp;

	list_for_each_entry(p, processes, list)
		release_one_process(p);

	list_for_each_entry_safe(p, tmp, processes, list)
		destroy_one_process(p);

	destroy_obj_trees();

	return 0;
}

static int attach_to_process(const struct process_info *p)
{
	if (attach_to_task(p->pid) != p->pid) {
		pr_err("failed to attach to process %d\n", p->pid);
		return -1;
	}
	return 0;
}

static bool is_mnt_file(struct process_info *p, int dir, const char *dentry,
			const char *source_mnt, dev_t device)
{
	struct stat st;
	ssize_t bytes;

	/* First check, that link points to the desired mount (if any).
	 * This is required to be able to switch between 2 different mounts
	 * with the same superblock.
	 */
	if (source_mnt) {
		char link[PATH_MAX];

		bytes = readlinkat(dir, dentry, link, PATH_MAX - 1);
		if (bytes < 0) {
			pr_perror("failed to read link %s", dentry);
			return -errno;
		}

		if (strncmp(link, source_mnt, strlen(source_mnt)))
			return false;

		if (link[strlen(source_mnt)] != '/')
			return false;
	}

	if (fstatat(dir, dentry, &st, 0)) {
		switch (errno) {
			case ENOENT:
			case ENOTDIR:
				break;
			default:
				pr_perror("failed to stat dentry %s", dentry);
		}
		return false;
	}
	return st.st_dev == device;
}

static int pid_is_kthread(pid_t pid)
{
	char path[PATH_MAX];
	char link[8];

	snprintf(path, PATH_MAX, "/proc/%d/exe", pid);
	if (readlink(path, link, 8) == -1)
		return true;
	return false;
}

int iterate_pids_list_name(const char *pids_list, void *data,
			   int (*actor)(pid_t pid, void *data),
			   const char *actor_name)
{
	char *list, *l, *pid;
	int err = 0;

	if (!pids_list) {
		pr_err("pids_list is NULL\n");
		return -EINVAL;
	}

	list = l = strdup(pids_list);
	if (!list) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	while ((pid = strsep(&l, "\n")) != NULL) {
		long p;

		if (!strlen(pid))
			continue;

		err = xatol(pid, &p);
		if (err) {
			pr_err("failed to convert pid %s to number\n", pid);
			break;
		}

		err = actor(p, data);
		if (err) {
			pr_err("actor %s failed for pid %d\n", actor_name, p);
			break;
		}
	}
	free(list);
	return err;
}

int get_pids_list(const char *tasks_file, char **list)
{
	char *pids_list;
	int err = -ENOMEM, fd;
	char buf[4096] = { };
	ssize_t bytes;

	fd = open(tasks_file, O_RDONLY);
	if (fd < 0) {
		pr_perror("failed to open %s", tasks_file);
		return -errno;
	}

	pids_list = NULL;
	do {
		bytes = read(fd, buf, sizeof(buf) - 1);
		if (bytes < 0) {
			pr_perror("failed to read %s", tasks_file);
			err = -errno;
			goto free_pids_list;
		}
		buf[bytes] = '\0';
		if (bytes) {
			pids_list = xstrcat(pids_list, "%s", buf);
			if (!pids_list) {
				pr_err("failed to allocate\n");
				goto close_fd;
			}
		}
	} while (bytes > 0);

	*list = pids_list;
	err = 0;

	pr_debug("Pids list:\n%s\n", *list);

close_fd:
	close(fd);
	return err;

free_pids_list:
	free(pids_list);
	goto close_fd;
}

static int fixup_source_path(const char *source_path,
			     const char *source_mnt, const char *target_mnt,
			     char *path, size_t size)
{
	const char *sp = source_path;
	ssize_t bytes;

	if (source_mnt) {
		size_t len = strlen(source_mnt);

		if (strncmp(source_path, source_mnt, len)) {
			pr_err("link %s doesn't start with source mnt %s\n",
					source_path, source_mnt);
			return -EINVAL;
		}
		sp += len;
	}

	bytes = snprintf(path, size, "%s%s", target_mnt, sp);
	if (bytes > size) {
		pr_err("target path is too long (%ld > %ld)\n",	bytes, size);
		return -ENOMEM;
	}
	return 0;
}

static int get_link_path(const char *link,
			 const char *source_mnt, const char *target_mnt,
			 char *path, size_t size)
{
	char source_path[PATH_MAX];
	ssize_t bytes;

	bytes = readlink(link, source_path, PATH_MAX - 1);
	if (bytes < 0) {
		pr_perror("failed to read link %s\n", link);
		return -errno;
	}
	source_path[bytes] = '\0';

	return fixup_source_path(source_path, source_mnt, target_mnt, path, size);
}

static int process_add_fd(struct process_info *p, const struct fd_info_s *fdi,
			  int target_fd)
{
	struct process_fd *pfd;

	pfd = malloc(sizeof(*pfd));
	if (!pfd) {
		pr_err("failed to allocate pfd\n");
		return -ENOMEM;
	}

	pfd->source_fd = fdi->fd;
	pfd->target_fd = target_fd;
	pfd->cloexec = (fdi->flags & O_CLOEXEC) ? FD_CLOEXEC : 0;
	pfd->pos = fdi->pos;
	list_add_tail(&pfd->list, &p->fds);
	p->fds_nr++;

	return 0;
}

static int process_add_mapping(struct process_info *p, int map_fd,
			       off_t start, off_t end,
			       int prot, int flags, unsigned long long pgoff)
{
	struct process_map *mfd;

	mfd = malloc(sizeof(*mfd));
	if (!mfd) {
		pr_err("failed to allocate mfd\n");
		return -ENOMEM;
	}

	mfd->map_fd = map_fd;
	mfd->start = start;
	mfd->end = end;
	mfd->prot = prot;
	mfd->flags = flags;
	mfd->pgoff = pgoff;
	list_add_tail(&mfd->list, &p->maps);
	p->maps_nr++;

	return 0;
}

static int copy_process_fd(struct process_info *p, int fd)
{
	int err;

	err = send_fd(p->pctl, true, fd);
	if (err < 0)
		return -1;

	return recv_fd(p->pctl, false);
}

static int parse_fdinfo(pid_t pid, int fd, unsigned *flags, long long *pos)
{
	char path[PATH_MAX];
	FILE *fdinfo;
	char buf[64];
	int err = 0;

	snprintf(path, PATH_MAX, "/proc/%d/fdinfo/%d", pid, fd);

	fdinfo = fopen(path, "r");
	if (!fdinfo) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	while (fgets(buf, 64, fdinfo) != NULL) {
		if (!strncmp(buf, "flags:\t", strlen("flags:\t"))) {
			if (sscanf(buf + strlen("flags:\t"), "%o", flags) != 1) {
				pr_err("failed to sscanf '%s'\n", buf);
				err = -EINVAL;
			}
		} else if (!strncmp(buf, "pos:\t", strlen("pos:\t"))) {
			if (sscanf(buf + strlen("pos:\t"), "%lli", pos) != 1) {
				pr_err("failed to sscanf '%s'\n", buf);
				err = -EINVAL;
			}
		}
	}
	if (err < 0)
		pr_err("failed to parse %s: %d\n", path, err);
	return err;
}

static int get_fd_info(struct process_info *p, int dir,
		const char *process_fd, struct fd_info_s *fdi)
{
	int local_fd, err;
	ssize_t bytes;
	char link[PATH_MAX];

	err = xatol(process_fd, (long *)&fdi->fd);
	if (err) {
		pr_err("failed to convert fd %s to number\n", process_fd);
		return err;
	}

	local_fd = copy_process_fd(p, fdi->fd);
	if (local_fd < 0) {
		pr_err("failed to copy /proc/%d/fd/%d\n", p->pid, fdi->fd);
		sleep(1000);
		return local_fd;
	}

	if (fstat(local_fd, &fdi->st)) {
		pr_perror("failed to stat fd %d", local_fd);
		err = -errno;
		goto close_local_fd;
	}

	err = parse_fdinfo(p->pid, fdi->fd, &fdi->flags, &fdi->pos);
	if (err) {
		pr_err("failed to get fd flags for /proc/%d/fd/%d", p->pid,
				fdi->fd);
		goto close_local_fd;
	}

	snprintf(link, PATH_MAX, "/proc/%d/fd/%d", p->pid, fdi->fd);
	bytes = readlink(link, fdi->path, PATH_MAX - 1);
	if (bytes < 0) {
		pr_perror("failed to read link %s\n", link);
		err = -errno;
		goto close_local_fd;
	}
	fdi->path[bytes] = '\0';

close_local_fd:
	close(local_fd);
	return err;
}

static int is_mnt_fd(const struct fd_info_s *fdi, const struct mounts_info_s *mi)
{
	/* First check, that link points to the desired mount (if any).
	 * This is required to be able to switch between 2 different mounts
	 * with the same superblock.
	 */
	if (mi->source_mnt) {
		if (strncmp(fdi->path, mi->source_mnt, strlen(mi->source_mnt)))
			return false;

		if (fdi->path[strlen(mi->source_mnt)] != '/')
			return false;
	}

	return fdi->st.st_dev == mi->src_dev;
}

static int collect_process_fd(struct process_info *p, int dir,
			      const char *process_fd, const void *data)
{
	int err, target_fd;
	const struct mounts_info_s *mi = data;
	struct replace_fd *rfd;
	char path[PATH_MAX];
	struct fd_info_s fdi;

	/* Fast path. In most of the cases opened file is accessible and
	 * shouldn't be replaced.
	 * Let's quickly check, whether it is so, and skip the fd copy and
	 * other checks.
	 */
	if (fstatat(dir, process_fd, &fdi.st, 0) == 0) {
		if (fdi.st.st_dev != mi->src_dev)
			return 0;
	}

	err = get_fd_info(p, dir, process_fd, &fdi);
	if (err)
		return err;

	if (!is_mnt_fd(&fdi, mi))
		return 0;

	err = collect_fd(p->pid, fdi.fd, &rfd);
	if (err) {
		pr_err("failed to add /proc/%d/fd/%d to tree\n", p->pid, fdi.fd);
		return err;
	}

	err = fixup_source_path(fdi.path, mi->source_mnt, mi->target_mnt,
				path, sizeof(path));
	if (err)
		return err;

	if (!rfd->file_obj) {
		char link[PATH_MAX];

		/* TODO This is a temporary solution !!! */
		snprintf(link, PATH_MAX, "/proc/%d/fd/%d", p->pid, fdi.fd);

		/* TODO it makes sense to create file objects (open files) only
		 * shared files here.
		 * Private files can be opened by the process itself */
		err = create_file_obj(path, fdi.flags, fdi.st.st_mode,
				      link, &rfd->file_obj);
		if (err) {
			pr_err("failed to open file object for /proc/%d/fd/%d\n",
					rfd->pid, rfd->fd);
			return err;
		}
	}

	target_fd = get_file_obj_fd(rfd->file_obj, fdi.flags);
	if (target_fd < 0)
		return target_fd;

	pr_debug("\t/proc/%d/fd/%d ---> %s (fd: %d, flags: 0%o)\n",
			p->pid, fdi.fd, path, target_fd, fdi.flags);

	return process_add_fd(p, &fdi, target_fd);
}

static int iterate_dir_name(const char *dpath, struct process_info *p,
		    int (*actor)(struct process_info *p, int dir,
				 const char *fd, const void *data),
		    const void *data,
		    const char *actor_name)
{
	struct dirent *dt;
	DIR *fdir;
	int dir;
	int err;

	fdir = opendir(dpath);
	if (!fdir) {
		pr_perror("failed to open %s", dpath);
		return -errno;
	}

	dir = dirfd(fdir);
	if (dir < 0) {
		pr_perror("failed to get fd for directory stream");
		err = -errno;
		goto close_dir;
	}

        while ((dt = readdir(fdir)) != NULL) {
		char *fd = dt->d_name;

		if (!strcmp(fd, ".") || !strcmp(fd, ".."))
			continue;

		err = actor(p, dir, fd, data);
		if (err) {
			pr_err("actor '%s' for %s/%s failed\n",
					actor_name, dpath, fd);
			break;
		}
	}

close_dir:
	closedir(fdir);
	return err;
}

static int collect_process_open_fds(struct process_info *p,
				    struct mounts_info_s *mi)
{
	char dpath[PATH_MAX];

	snprintf(dpath, PATH_MAX, "/proc/%d/fd", p->pid);
	return iterate_dir_name(dpath, p, collect_process_fd, mi, "collect_process_fd");
}

static int collect_map_file(struct process_info *p,
			    unsigned long start, unsigned long end,
			    mode_t mode, const char *path,
			    int prot, int flags, unsigned long long pgoff)
{
	int fd, map_fd = -1, err;

	fd = open(path, mode);
	if (fd < 0) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	err = collect_map_fd(fd, path, mode, &map_fd);
	if (err) {
		pr_err("failed to collect map fd for path %s\n", path);
		goto close_fd;
	}

	pr_debug("\t/proc/%d/map_files/%lx-%lx ---> %s (fd: %d)\n",
			p->pid, start, end, path, map_fd);

	err = process_add_mapping(p, map_fd, start, end, prot, flags, pgoff);

close_fd:
	if ((fd != map_fd) || err)
		close(fd);
	return err;
}

static int map_open_mode(int map_files_fd,
			    unsigned long start, unsigned long end,
			    mode_t *mode)
{
	char map_file[64];
	struct stat st;

	sprintf(map_file, "%lx-%lx", start, end);

	if (fstatat(map_files_fd, map_file, &st, AT_SYMLINK_NOFOLLOW) < 0) {
		pr_err("failed to stat map file %s", map_file);
		return -errno;
	}

	switch(st.st_mode & 0600) {
		case 0200:
			*mode = O_WRONLY;
			break;
		case 0400:
			*mode = O_RDONLY;
			break;
		case 0600:
			*mode = O_RDWR;
			break;
		default:
			pr_err("unsupported mode for map file: 0%o\n",
			st.st_mode & 0600);
			return -EINVAL;
	}
	return 0;
}

static bool is_mnt_map(struct process_info *p, int dir,
		       unsigned long start, unsigned long end,
		       struct mounts_info_s *mi)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%lx-%lx", start, end);
	return is_mnt_file(p, dir, path, mi->source_mnt, mi->src_dev);
}

static int map_prot(char r, char w, char x)
{
	int prot = 0;

	if (r == 'r')
		prot |= PROT_READ;
	if (w == 'w')
		prot |= PROT_WRITE;
	if (x == 'x')
		prot |= PROT_EXEC;

	return prot;
}

static int collect_process_maps(struct process_info *p,
				struct mounts_info_s *mi)
{
	char map[PATH_MAX];
	FILE *fmap;
	int err = -ENOENT;
	int dir;

	snprintf(map, PATH_MAX, "/proc/%d/map_files", p->pid);
	dir = open(map, O_RDONLY | O_DIRECTORY);
	if (dir < 0) {
		pr_perror("failed to open %s", map);
		return -errno;
	}

	snprintf(map, PATH_MAX, "/proc/%d/maps", p->pid);
	fmap = fopen(map, "r");
	if (!fmap) {
		pr_perror("failed to open %s", map);
		err = -errno;
		goto close_dir;
	}


	while (fgets(map, sizeof(map), fmap)) {
		char path[PATH_MAX];
		unsigned long start, end, ino;
		int ret, path_off;
		char *map_file;
		mode_t mode = 0;
		char r, w, x, s;
		unsigned long long pgoff;

		map[strlen(map)-1] = '\0';

		ret = sscanf(map, "%lx-%lx %c%c%c%c %llx %*x:%*x %lu %n",
				&start, &end, &r, &w, &x, &s, &pgoff, &ino, &path_off);
		if (ret != 8) {
			pr_err("failed to parse '%s': %d\n", map, ret);
			err = -EINVAL;
			goto close_fmap;
		}

		if (!ino)
			continue;

		if (!is_mnt_map(p, dir, start, end, mi))
			continue;

		map_file = map + path_off;

		err = fixup_source_path(map_file,
					mi->source_mnt, mi->target_mnt,
					path, sizeof(path));
		if (err)
			goto close_fmap;

		err = map_open_mode(dir, start, end, &mode);
		if (err)
			goto close_fmap;

		err = collect_map_file(p, start, end, mode, path,
				       map_prot(r, w, x),
				       s == 's' ? MAP_SHARED : MAP_PRIVATE,
				       pgoff);
		if (err)
			goto close_fmap;
	}
	err = 0;
close_fmap:
	fclose(fmap);
close_dir:
	close(dir);
	return err;

}

static int get_process_env(struct process_info *p,
			   struct mounts_info_s *mi,
			   const char *dentry, char *path, size_t size)
{
	char link[PATH_MAX];

	snprintf(link, PATH_MAX, "/proc/%d/%s", p->pid, dentry);
	return get_link_path(link, mi->source_mnt, mi->target_mnt, path, size);
}

static int open_process_env(struct process_info *p,
			    struct mounts_info_s *mi,
			    const char *dentry)
{
	char path[PATH_MAX];
	int err, fd;

	err = get_process_env(p, mi, dentry, path, sizeof(path));
	if (err)
		return err;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	pr_debug("\t/proc/%d/%s ---> %s (fd %d)\n", p->pid, dentry, path, fd);

	return fd;
}

static int collect_process_fs(struct process_info *p,
			       struct mounts_info_s *mi,
			       int dir)
{
	bool mnt_cwd, mnt_root;
	int err;
	bool exists;

	mnt_cwd = is_mnt_file(p, dir, "cwd", mi->source_mnt, mi->src_dev);
	mnt_root = is_mnt_file(p, dir, "root", mi->source_mnt, mi->src_dev);

	if (!mnt_cwd && ! mnt_root)
		return 0;

	err = collect_fs_struct(p->pid, &exists);
	if (err) {
		pr_err("failed to collect process %d fs\n", p->pid);
		return err;
	}
	if (exists) {
		pr_info("ignoring process %d fs\n", p->pid);
		return 0;
	}

	if (mnt_cwd) {
		p->fs.cwd_fd = open_process_env(p, mi, "cwd");
		if (p->fs.cwd_fd < 0)
			return p->fs.cwd_fd;
	}

	if (mnt_root) {
		char path[PATH_MAX];

		err = get_process_env(p, mi, "root", path, sizeof(path));
		if (err)
			return err;

		p->fs.root= strdup(path);
		if (!p->fs.root)
			return -ENOMEM;
	}
	return 0;
}

static int collect_process_exe(struct process_info *p,
			       struct mounts_info_s *mi,
			       int dir)
{
	if (!is_mnt_file(p, dir, "exe", mi->source_mnt, mi->src_dev))
		return 0;

	p->exe_fd = open_process_env(p, mi, "exe");
	if (p->exe_fd < 0)
		return p->exe_fd;

	return 0;
}

static int collect_process_env(struct process_info *p,
			       struct mounts_info_s *mi)
{
	int dir, err;
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "/proc/%d", p->pid);
	dir = open(path, O_RDONLY | O_DIRECTORY);
	if (dir < 0) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	err = collect_process_exe(p, mi, dir);
	if (err)
		goto close_dir;

	err = collect_process_fs(p, mi, dir);

close_dir:
	close(dir);
	return err;
}

static int collect_process_fds(struct process_info *p,
			       struct mounts_info_s *mi)
{
	int err;

	if (fd_table_exists(p->pid)) {
		pr_info("\t/proc/%d/fd ---> ignoring (shared)\n", p->pid);
		return 0;
	}

	err = collect_process_open_fds(p, mi);
	if (err)
		return err;

	if (p->fds_nr)
		err = collect_fd_table(p->pid);

	return err;
}

static int examine_one_process(struct process_info *p, struct mounts_info_s *mi)
{
	int err;

	pr_debug("Process %d: examining...\n", p->pid);

	err = collect_process_env(p, mi);
	if (err)
		return err;

	err = collect_process_fds(p, mi);
	if (err)
		goto destroy_process_fds;

	err = collect_process_maps(p, mi);
	if (err)
		goto destroy_process_maps;

	return 0;

destroy_process_maps:
	destroy_process_maps(p);
destroy_process_fds:
	destroy_process_fds(p);
	return err;
}

static int examine_processes(struct list_head *collection,
			     dev_t src_dev,
			     const char *source_mnt, const char *target_mnt)
{
	struct mounts_info_s mi = {
		.src_dev = src_dev,
		.source_mnt = source_mnt,
		.target_mnt = target_mnt,
	};
	struct process_info *p;
	int err;

	list_for_each_entry(p, collection, list) {
		err = examine_one_process(p, &mi);
		if (err)
			return err;
	}
	return 0;
}

int examine_processes_by_dev(struct list_head *collection,
			     dev_t src_dev, const char *target_mnt)
{
	return examine_processes(collection, src_dev, NULL, target_mnt);
}

int examine_processes_by_mnt(struct list_head *collection,
			     const char *source_mnt, const char *target_mnt)
{
	struct stat st;

	if (stat(source_mnt, &st) < 0) {
		pr_perror("failed to stat %s", source_mnt);
		return -errno;
	}

	return examine_processes(collection, st.st_dev, source_mnt, target_mnt);
}

static struct process_info *create_process_info(pid_t pid)
{
	struct process_info *p;

	p = malloc(sizeof(*p));
	if (!p) {
		pr_err("failed to allocate process\n");
		return NULL;
	}

	p->pid = pid;
	p->fds_nr = 0;
	p->maps_nr = 0;
	p->exe_fd = -1;
	p->fs.cwd_fd = -1;
	p->fs.root = NULL;
	p->pctl = NULL;
	p->orig_st = TASK_UNDEF;
	INIT_LIST_HEAD(&p->fds);
	INIT_LIST_HEAD(&p->maps);

	return p;
}

static int collect_one_process(pid_t pid, void *data)
{
	struct process_info *p;
	struct list_head *collection = data;

	if (pid_is_kthread(pid)) {
		pr_debug("Process %d: kthread, skipping\n", pid);
		return 0;
	}

	p = create_process_info(pid);
	if (!p)
		return -ENOMEM;

	if (attach_to_process(p) < 0) {
		free(p);
		return -EPERM;
	}

	list_add_tail(&p->list, collection);
	return 0;
}

int collect_processes(const char *pids, struct list_head *collection)
{
	pr_debug("Collecting processes...\n");
	return iterate_pids_list(pids, collection, collect_one_process);
}
