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
#include "link_remap.h"

struct fd_info_s {
	int             process_fd;
	int		local_fd;
	struct stat     st;
	unsigned        flags;
	long long	pos;
	char            path[PATH_MAX];
	char            cwd[PATH_MAX];
};

static int seize_one_process(struct process_info *p)
{
	p->orig_st = wait_task_seized(p->pid);
	if (p->orig_st < 0) {
		pr_err("failed to seize process %d\n", p->pid);
		return -EPERM;
	}
	pr_info("    %d seized\n", p->pid);
	return 0;
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
#if 0
static int detach_from_process(const struct process_info *p)
{
	if (detach_from_task(p->pid, p->orig_st)) {
		pr_err("failed to detach from process %d\n", p->pid);
		return -EPERM;
	}
	pr_info("    %d released\n", p->pid);
	return 0;
}
#endif

static void process_resource_release(struct process_resource *res)
{
	if (!res->replaced)
		put_file_obj(res->fobj);
}

static void release_process_map(struct process_map *pm)
{
	process_resource_release(&pm->res);
	free(pm);
}

static void release_process_maps(struct process_info *p)
{
	struct process_map *pm, *tmp;

	if (!p->maps_nr)
		return;

	list_for_each_entry_safe(pm, tmp, &p->maps, list) {
		list_del(&pm->list);
		release_process_map(pm);
	}
}

static void release_process_fd(struct process_fd *pfd)
{
	process_resource_release(&pfd->res);
	free(pfd);
}

static void release_process_fds(struct process_info *p)
{
	struct process_fd *pfd, *tmp;

	if (!p->fds_nr)
		return;

	list_for_each_entry_safe(pfd, tmp, &p->fds, list) {
		list_del(&pfd->list);
		release_process_fd(pfd);
	}
}

static void release_process_exe(struct process_info *p)
{
	struct process_resource *exe = &p->exe;

	if (exe->fobj)
		process_resource_release(exe);
}

static void release_process_fs(struct process_info *p)
{
	struct process_fs *fs = &p->fs;
	struct process_resource *cwd = &fs->cwd;

	if (cwd->fobj)
		process_resource_release(cwd);
	free(fs->root);
}

static void release_process_resources(struct process_info *p)
{
	release_process_maps(p);
	release_process_fds(p);
	release_process_exe(p);
	release_process_fs(p);
}

static void detach_one_process(struct process_info *p)
{
	if (p->pctl)
		(void) destroy_parasite_ctl(p->pid, p->pctl);
//	(void) detach_from_process(p);
	list_del(&p->list);
	free(p);
}

static void release_shared_resources(void)
{
	destroy_obj_trees();
	destroy_link_remap_tree();
}

void release_processes(struct list_head *processes)
{
	struct process_info *p, *tmp;

	list_for_each_entry(p, processes, list)
		release_process_resources(p);

	list_for_each_entry_safe(p, tmp, processes, list)
		detach_one_process(p);

	release_shared_resources();
}

static int attach_to_process(const struct process_info *p)
{
	if (attach_to_task(p->pid) != p->pid) {
		pr_err("failed to attach to process %d\n", p->pid);
		return -1;
	}
	return 0;
}

static bool is_mnt_file(int dir, const char *dentry,
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
		int p;

		if (!strlen(pid))
			continue;

		err = xatoi(pid, &p);
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

static int transform_path(const char *source_path,
			  const char *source_mnt, const char *target_mnt,
			  char *dest_path, size_t size)
{
	const char *sp = source_path;

	if (source_path == dest_path) {
		pr_err("source and destination are the same\n");
		return -EINVAL;
	}

	if (source_mnt) {
		size_t len = strlen(source_mnt);

		if (strncmp(sp, source_mnt, len)) {
			pr_err("link %s doesn't start with source mnt %s\n",
					sp, source_mnt);
			return -EINVAL;
		}
		sp += len;
	}

	if (size <= strlen(target_mnt) + strlen(sp)) {
		pr_err("resulting path is too long (%ld >= %ld)\n",
				strlen(target_mnt) + strlen(sp), size);
		return -ENOMEM;
	}

	strcpy(dest_path, target_mnt);
	strcat(dest_path, sp);

	return 0;
}

int fixup_source_path(char *source_path, size_t source_size,
			     const char *source_mnt, const char *target_mnt)
{
	char buf[PATH_MAX + 1] = { };

	if (source_size >= sizeof(buf)) {
		pr_err("source path size is too big: %ld\n", source_size);
		return -E2BIG;
	}

	strncpy(buf, source_path, source_size);

	return transform_path(buf, source_mnt, target_mnt,
			      source_path, source_size);
}

static int get_link_path(const char *link,
			 const char *source_mnt, const char *target_mnt,
			 char *path, size_t size)
{
	ssize_t bytes;

	bytes = readlink(link, path, PATH_MAX - 1);
	if (bytes < 0) {
		pr_perror("failed to read link %s\n", link);
		return -errno;
	}
	path[bytes] = '\0';

	return fixup_source_path(path, size, source_mnt, target_mnt);
}

static int process_add_fd(struct process_info *p, const struct fd_info_s *fdi,
			  void *fobj)
{
	struct process_fd *pfd;

	pfd = malloc(sizeof(*pfd));
	if (!pfd) {
		pr_err("failed to allocate pfd\n");
		return -ENOMEM;
	}

	pfd->info.source_fd = fdi->process_fd;
	pfd->info.cloexec = (fdi->flags & O_CLOEXEC) ? FD_CLOEXEC : 0;
	pfd->info.pos = fdi->pos;
	pfd->res.replaced = false;
	pfd->res.fobj = fobj;
	list_add_tail(&pfd->list, &p->fds);
	p->fds_nr++;

	return 0;
}

static int process_add_mapping(struct process_info *p,
			       off_t start, off_t end,
			       int prot, int flags, unsigned long long pgoff,
			       void *fobj)
{
	struct process_map *pm;

	pm = malloc(sizeof(*pm));
	if (!pm) {
		pr_err("failed to allocate pm\n");
		return -ENOMEM;
	}

	pm->info.start = start;
	pm->info.end = end;
	pm->info.prot = prot;
	pm->info.flags = flags;
	pm->info.pgoff = pgoff;
	pm->res.replaced = false;
	pm->res.fobj = fobj;
	list_add_tail(&pm->list, &p->maps);
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
	fclose(fdinfo);
	return err;
}

static void put_fd_info(struct fd_info_s *fdi)
{
	close(fdi->local_fd);
}

static int get_fd_info(struct process_info *p, int dir,
		const char *process_fd, const struct replace_info_s *ri,
		struct fd_info_s *fdi)
{
	int err;
	ssize_t bytes;

	err = xatoi(process_fd, &fdi->process_fd);
	if (err) {
		pr_err("failed to convert fd %s to number\n", process_fd);
		return err;
	}

	fdi->local_fd = copy_process_fd(p, fdi->process_fd);
	if (fdi->local_fd < 0) {
		pr_err("failed to copy /proc/%d/fd/%d ---> %s\n",
				p->pid, fdi->process_fd, fdi->path);
		return fdi->local_fd;
	}

	if (fstat(fdi->local_fd, &fdi->st)) {
		pr_perror("failed to stat fd %d", fdi->local_fd);
		err = -errno;
		goto close_local_fd;
	}

	err = parse_fdinfo(p->pid, fdi->process_fd, &fdi->flags, &fdi->pos);
	if (err) {
		pr_err("failed to get fd flags for /proc/%d/fd/%d", p->pid,
				fdi->process_fd);
		goto close_local_fd;
	}

	snprintf(fdi->path, PATH_MAX, "/proc/%d/fd/%d", p->pid, fdi->process_fd);
	bytes = readlink(fdi->path, fdi->path, PATH_MAX - 1);
	if (bytes < 0) {
		pr_perror("failed to read link %s\n", fdi->path);
		err = -errno;
		goto close_local_fd;
	}
	fdi->path[bytes] = '\0';

	if (S_ISSOCK(fdi->st.st_mode)) {
		snprintf(fdi->cwd, PATH_MAX, "/proc/%d/cwd", p->pid);
		bytes = readlink(fdi->cwd, fdi->cwd, PATH_MAX - 1);
		if (bytes < 0) {
			pr_perror("failed to read link %s\n", fdi->cwd);
			err = -errno;
			goto close_local_fd;
		}
		fdi->cwd[bytes] = '\0';
		err = fixup_source_path(fdi->cwd, sizeof(fdi->cwd),
					ri->source_mnt, ri->target_mnt);
	} else
		err = fixup_source_path(fdi->path, sizeof(fdi->path),
					ri->source_mnt, ri->target_mnt);

close_local_fd:
	if (err)
		close(fdi->local_fd);
	return err;
}

static int is_mnt_fd(const struct fd_info_s *fdi, const struct replace_info_s *ri)
{
	if (S_ISSOCK(fdi->st.st_mode)) {
		void *data;

		if (find_unix_socket(fdi->st.st_ino, &data) != -ENOENT)
			return true;

		return false;
	}

	/* First check, that link points to the desired mount (if any).
	 * This is required to be able to switch between 2 different mounts
	 * with the same superblock.
	 */
	if (ri->source_mnt) {
		if (strncmp(fdi->path, ri->source_mnt, strlen(ri->source_mnt)))
			return false;

		if (fdi->path[strlen(ri->source_mnt)] != '/')
			return false;
	}

	return fdi->st.st_dev == ri->src_dev;
}

struct fd_collect_s {
	pid_t		pid;
	int		fd;
};

static int collect_process_fd_cb(void *cb_data, void *new_fobj, void **res_fobj)
{
	int err;
	struct fd_collect_s *fdc = cb_data;

	err = collect_fd(fdc->pid, fdc->fd, new_fobj, res_fobj);
	if (err)
		pr_err("failed to add /proc/%d/fd/%d to tree\n",
				fdc->pid, fdc->fd);
	return err;
}

static int collect_process_fd(struct process_info *p,
			      const struct replace_info_s *ri,
			      const struct fd_info_s *fdi)
{
	struct fd_collect_s fdc = {
		.pid = p->pid,
		.fd = fdi->process_fd,
	};
	void *fobj;
	int err;
	const char *path;

	if (!S_ISSOCK(fdi->st.st_mode))
		path = fdi->path;
	else
		path = fdi->cwd;

	err = get_file_obj(path, fdi->flags, fdi->st.st_mode,
			   fdi->local_fd, ri,
			   &fdc, collect_process_fd_cb,
			   &fobj);
	if (err)
		return err;

	pr_debug("    /proc/%d/fd/%d ---> %s (flags: 0%o)\n",
			p->pid, fdi->process_fd, fdi->path, fdi->flags);

	return process_add_fd(p, fdi, fobj);
}

static bool fd_skip_fast(const struct process_info *p, int dir,
			 const char *process_fd,
			 const struct replace_info_s *ri)
{
	struct stat st;

	if (fstatat(dir, process_fd, &st, 0))
		return false;

	if (S_ISSOCK(st.st_mode)) {
		if (is_parasite_sock(p->pctl, st.st_ino))
			return true;
		return false;
	}

	return st.st_dev != ri->src_dev;
}

static int examine_process_fd(struct process_info *p, int dir,
			      const char *process_fd, const void *data)
{
	int err;
	const struct replace_info_s *ri = data;
	struct fd_info_s fdi;

	/* Fast path. In most of the cases opened file is accessible and
	 * shouldn't be replaced.
	 * Let's quickly check, whether it is so, and skip the fd copy and
	 * other checks.
	 */
	if (fd_skip_fast(p, dir, process_fd, ri))
		return 0;

	err = get_fd_info(p, dir, process_fd, ri, &fdi);
	if (err)
		return err;

	if (is_mnt_fd(&fdi, ri))
		err = collect_process_fd(p, ri, &fdi);

	put_fd_info(&fdi);
	return err;
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
	int err = 0;

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
				    const struct replace_info_s *ri)
{
	char dpath[PATH_MAX];

	snprintf(dpath, PATH_MAX, "/proc/%d/fd", p->pid);
	return iterate_dir_name(dpath, p, examine_process_fd, ri, "examine_process_fd");
}

struct open_path_collect_s {
	const char	*path;
	unsigned	flags;
};

static int collect_open_path_cb(void *cb_data, void *new_fobj, void **res_fobj)
{
	int err;
	struct open_path_collect_s *opath = cb_data;

	err = collect_open_path(opath->path, opath->flags, new_fobj, res_fobj);
	if (err < 0) {
		pr_err("failed to collect map fd for path %s\n", opath->path);
		return err;
	}
	return err;
}

static int collect_map_file(struct process_info *p, const struct replace_info_s *ri,
			    unsigned long start, unsigned long end,
			    unsigned open_flags, const char *map_path,
			    int prot, int map_flags, unsigned long long pgoff)
{
	struct open_path_collect_s opath = {
		.path = map_path,
		.flags = open_flags,
	};
	void *fobj;
	int err;

	err = get_file_obj(map_path, open_flags, S_IFREG, -1, ri,
			   &opath, collect_open_path_cb, &fobj);
	if (err)
		return err;

	pr_debug("    /proc/%d/map_files/%lx-%lx ---> %s (flags: 0%o)\n",
			p->pid, start, end, map_path, open_flags);

	return process_add_mapping(p, start, end, prot, map_flags, pgoff, fobj);
}

static int map_open_flags(int map_files_fd,
			  unsigned long start, unsigned long end,
			  unsigned *flags)
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
			*flags = O_WRONLY;
			break;
		case 0400:
			*flags = O_RDONLY;
			break;
		case 0600:
			*flags = O_RDWR;
			break;
		default:
			pr_err("unsupported mode for map file: 0%o\n",
					st.st_mode & 0600);
			return -EINVAL;
	}
	return 0;
}

static bool is_mnt_map(int dir,
		       unsigned long start, unsigned long end,
		       const struct replace_info_s *ri)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%lx-%lx", start, end);
	return is_mnt_file(dir, path, ri->source_mnt, ri->src_dev);
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

static int collect_process_map_files(struct process_info *p,
				     const struct replace_info_s *ri)
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
		unsigned flags = O_RDONLY;
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

		if (!is_mnt_map(dir, start, end, ri))
			continue;

		map_file = map + path_off;

		err = transform_path(map_file, ri->source_mnt, ri->target_mnt,
				     path, sizeof(path));
		if (err)
			goto close_fmap;

		err = map_open_flags(dir, start, end, &flags);
		if (err)
			goto close_fmap;

		err = collect_map_file(p, ri, start, end, flags, path,
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
			   const struct replace_info_s *ri,
			   const char *dentry, char *path, size_t size)
{
	char link[PATH_MAX];

	snprintf(link, PATH_MAX, "/proc/%d/%s", p->pid, dentry);
	return get_link_path(link, ri->source_mnt, ri->target_mnt, path, size);
}

static int collect_process_env(struct process_info *p,
			       const struct replace_info_s *ri,
			       const char *dentry, mode_t mode,
			       void **fobj)
{
	char path[PATH_MAX] = { };
	struct open_path_collect_s opath = {
		.path = path,
		.flags = O_RDONLY,
	};
	int err;

	err = get_process_env(p, ri, dentry, path, sizeof(path));
	if (err)
		return err;

	if (!strlen(path)) {
		pr_err("empty link /proc/%d/%s\n", p->pid, dentry);
		return -EINVAL;
	}

	err = get_file_obj(path, O_RDONLY, mode, -1, ri,
			   &opath, collect_open_path_cb,
			   fobj);
	if (err)
		return err;

	pr_debug("    /proc/%d/%s ---> %s\n", p->pid, dentry, path);

	return 0;
}

static int collect_process_exe(struct process_info *p,
			       const struct replace_info_s *ri)
{
	int dir, err;
	char path[PATH_MAX];
	bool mnt_exe;

	snprintf(path, PATH_MAX, "/proc/%d", p->pid);
	dir = open(path, O_RDONLY | O_DIRECTORY);
	if (dir < 0) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	mnt_exe = is_mnt_file(dir, "exe", ri->source_mnt, ri->src_dev);

	close(dir);

	if (!mnt_exe)
		return 0;

	err = collect_process_env(p, ri, "exe", S_IFREG, &p->exe.fobj);
	if (err)
		return err;
	return 0;
}

static int collect_process_maps(struct process_info *p,
				const struct replace_info_s *ri)
{
	int err;
	pid_t pid;

	pid = mm_exists(p->pid);
	if (pid) {
		pr_info("    /proc/%d/map_files ---> ignoring (shared with process %d)\n",
				p->pid, pid);
		return 0;
	}

	err = collect_process_exe(p, ri);
	if (err)
		return err;

	err = collect_process_map_files(p, ri);
	if (err)
		return err;

	if (p->maps_nr)
		err = collect_mm(p->pid);

	return err;
}

static int collect_process_cwd_root(struct process_info *p,
				    const struct replace_info_s *ri)
{
	bool mnt_cwd, mnt_root;
	int dir, err;
	char path[PATH_MAX];
	struct process_fs *fs = &p->fs;

	snprintf(path, PATH_MAX, "/proc/%d", p->pid);
	dir = open(path, O_RDONLY | O_DIRECTORY);
	if (dir < 0) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	mnt_cwd = is_mnt_file(dir, "cwd", ri->source_mnt, ri->src_dev);
	mnt_root = is_mnt_file(dir, "root", ri->source_mnt, ri->src_dev);

	close(dir);

	if (!mnt_cwd && ! mnt_root)
		return 0;

	if (mnt_cwd) {
		err = collect_process_env(p, ri, "cwd", S_IFDIR, &fs->cwd.fobj);
		if (err)
			return err;
	}

	if (mnt_root) {
		char path[PATH_MAX] = { };

		err = get_process_env(p, ri, "root", path, sizeof(path));
		if (err)
			return err;

		fs->root= strdup(path);
		if (!fs->root)
			return -ENOMEM;
	}
	return 0;
}

static int collect_process_fs(struct process_info *p,
			      const struct replace_info_s *ri)
{
	int err;
	pid_t pid;
	struct process_fs *fs = &p->fs;

	pid = fs_struct_exists(p->pid);
	if (pid) {
		pr_info("    /proc/%d/<root,cwd> ---> ignoring (shared with process %d)\n",
				p->pid, pid);
		return 0;
	}

	err = collect_process_cwd_root(p, ri);
	if (err)
		return err;

	if (fs->cwd.fobj || fs->root) {
		err = collect_fs_struct(p->pid);
		if (err)
			pr_err("failed to collect process %d fs\n", p->pid);
	}

	return err;
}

static int collect_process_fds(struct process_info *p,
			       const struct replace_info_s *ri)
{
	int err;
	pid_t pid;

	pid = fd_table_exists(p->pid);
	if (pid) {
		pr_info("    /proc/%d/fd ---> ignoring (shared with process %d)\n",
				p->pid, pid);
		return 0;
	}

	err = collect_process_open_fds(p, ri);
	if (err)
		return err;

	if (p->fds_nr)
		err = collect_fd_table(p->pid);

	return err;
}

static int examine_one_process(struct process_info *p, const struct replace_info_s *ri)
{
	int err;

	pr_debug("Process %d: examining...\n", p->pid);

	err = set_parasite_ctl(p->pid, &p->pctl);
	if (err)
		return err;

	err = collect_process_fs(p, ri);
	if (err)
		return err;

	err = collect_process_fds(p, ri);
	if (err)
		goto destroy_process_fds;

	err = collect_process_maps(p, ri);
	if (err)
		goto destroy_process_maps;

	return 0;

destroy_process_maps:
	release_process_maps(p);
destroy_process_fds:
	release_process_fds(p);
	return err;
}

static bool process_needs_resources_swap(struct process_info *p)
{
	if (p->fds_nr)
		return true;
	if (p->maps_nr)
		return true;
	if (p->fs.cwd.fobj)
		return true;
	if (p->fs.root)
		return true;
	return false;
}

int examine_processes(struct list_head *collection,
		      const struct replace_info_s *ri)
{
	struct process_info *p, *tmp;
	int err;

	list_for_each_entry_safe(p, tmp, collection, list) {
		err = examine_one_process(p, ri);
		if (err)
			return err;

		if (!process_needs_resources_swap(p)) {
			pr_info("Process %d doesn't need resources swap\n", p->pid);
			detach_one_process(p);
		}
	}
	return 0;
}

static struct process_info *create_process_info(pid_t pid)
{
	struct process_info *p;

	p = malloc(sizeof(*p));
	if (!p) {
		pr_err("failed to allocate process\n");
		return NULL;
	}
	memset(p, 0, sizeof(*p));

	p->pid = pid;
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
