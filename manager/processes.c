#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>

#include "include/list.h"
#include "include/log.h"
#include "include/util.h"
#include "include/shm.h"

#include "spfs.h"
#include "fd_tree.h"
#include "swapfd.h"
#include "processes.h"

char *ns_names[NS_MAX] = {
	[NS_UTS] = "uts",
	[NS_MNT] = "mnt",
	[NS_NET] = "net",
	[NS_PID] = "pid",
	[NS_USER] = "user"
};

int open_ns(pid_t pid, const char *ns_type)
{
	int fd;
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "/proc/%d/ns/%s", pid, ns_type);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("failed to open %s", path);
		return -errno;
	}
	return fd;
}

int set_namespaces(int *ns_fds, unsigned ns_mask)
{
	int ns_type, err;

	for (ns_type = NS_UTS; ns_type < NS_MAX; ns_type++) {
		if ((ns_mask & (1 << ns_type)) == 0)
			continue;

		if (ns_fds[ns_type] < 0) {
			pr_err("failed to set %s ns: fd is closed\n",
					ns_names[ns_type]);
			continue;
		}

		err = setns(ns_fds[ns_type], 0);
		if (err) {
			pr_perror("failed to set ns by fd %d", ns_fds[ns_type]);
			break;
		}
	}
	return err;
}

int close_namespaces(int *ns_fds)
{
	int ns_type;

	for (ns_type = NS_UTS; ns_type < NS_MAX; ns_type++) {
		if (ns_fds[ns_type] < 0)
			continue;
		close(ns_fds[ns_type]);
		ns_fds[ns_type] = -1;
	}
	return 0;
}

int open_namespaces(pid_t pid, int *ns_fds)
{
	int err, ns_type;

	for (ns_type = NS_UTS; ns_type < NS_MAX; ns_type++) {
		err = open_ns(pid, ns_names[ns_type]);
		if (err < 0)
			goto close_saved_fd;
		ns_fds[ns_type] = err;
	}

	return 0;

close_saved_fd:
	(void)close_namespaces(ns_fds);
	return err;
}

int change_namespaces(pid_t pid, unsigned ns_mask, int *orig_ns_fds[])
{
	int ns_fds[NS_MAX] = {
		-1, -1, -1, -1, -1
	};
	int err;

	if (orig_ns_fds) {
		err = open_namespaces(getpid(), ns_fds);
		if (err)
			return err;
	}

	err = open_namespaces(pid, ns_fds);
	if (err)
		return err;

	err = set_namespaces(ns_fds, ns_mask);

	(void)close_namespaces(ns_fds);
	return err;
}

static int seize_one_process(const struct process_info *p)
{
	if (wait_task_seized(p->pid)) {
		pr_err("failed to seize process %d\n", p->pid);
		return -EPERM;
	}
	pr_debug("seized process %d\n", p->pid);
	return 0;
}

int seize_processes(struct list_head *processes)
{
	const struct process_info *p;

	list_for_each_entry(p, processes, list) {
		if (seize_one_process(p))
			return -EPERM;
	}
	return 0;
}

static int detach_from_process(const struct process_info *p)
{
	if (detach_from_task(p->pid)) {
		pr_err("failed to detach from process %d\n", p->pid);
		return -EPERM;
	}
	pr_debug("detached from process %d\n", p->pid);
	return 0;
}

int release_processes(struct list_head *processes)
{
	struct process_info *p, *tmp;

	list_for_each_entry_safe(p, tmp, processes, list) {
		(void) detach_from_process(p);
		list_del(&p->list);
		free(p);
	}
	return 0;
}

static int attach_to_process(const struct process_info *p)
{
	if (attach_to_task(p->pid) != p->pid) {
		pr_err("failed to attach to process %d\n", p->pid);
		return -1;
	}
	pr_debug("attached to process %d\n", p->pid);
	return 0;
}

static bool is_mnt_fd(int dir, const char *fd, dev_t device)
{
	struct stat st;

	if (fstatat(dir, fd, &st, 0)) {
		switch (errno) {
			case ENOENT:
			case ENOTDIR:
				break;
			default:
				pr_perror("failed to stat fd %s", fd);
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

int iterate_pids_list_name(const char *pids_list, void *data, const void *filter,
			   int (*actor)(pid_t pid, void *data, const void *filter),
			   const char *actor_name)
{
	char *list, *pid;
	int err = 0;

	if (!pids_list) {
		pr_err("pids_list is NULL\n");
		return -EINVAL;
	}

	list = strdup(pids_list);
	if (!list) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	while ((pid = strsep(&list, "\n")) != NULL) {
		long p;

		if (!strlen(pid))
			continue;

		err = xatol(pid, &p);
		if (err) {
			pr_err("failed to convert pid %s to number\n", pid);
			break;
		}

		if (pid_is_kthread(p)) {
			pr_debug("Skipping kthread %d\n", pid);
			continue;
		}

		err = actor(p, data, filter);
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

static int get_fd_flags(pid_t pid, int fd)
{
	char path[PATH_MAX];
	FILE *fdinfo;
	char buf[64];
	int flags = -ENOENT;

	snprintf(path, PATH_MAX, "/proc/%d/fdinfo/%d", pid, fd);

	fdinfo = fopen(path, "r");
	if (!fdinfo) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	while (fgets(buf, 64, fdinfo) != NULL) {
		pr_debug("fdinfo string: %s", buf);
		if (strncmp(buf, "flags", strlen("flags")))
			continue;
		if (sscanf(buf, "flags:\t%o", &flags) != 1) {
			pr_err("failed to sscanf '%s'\n", buf);
			flags = -EINVAL;
		}
		break;
	}
	if (flags < 0)
		pr_err("failed to get %s flags: %d\n", path, flags);
	return flags;
}

static void *fifo_file_obj(const char *path, unsigned flags, struct replace_fd *rfd)
{
	pr_err("fifo is not supported yet\n");
	return NULL;
}

static void *reg_file_obj(const char *path, unsigned flags, struct replace_fd *rfd)
{
	int fd;

	fd = open(path, flags);
	if (fd < 0) {
		pr_perror("failed to open %s", path);
		return NULL;
	}
	return (void *)(long)fd;
}

static int create_file_obj(const char *path, unsigned flags, struct replace_fd *rfd)
{
	/* TODO move these actors to tree creation and place them on replace_fd
	 * structure */
	switch (rfd->mode & S_IFMT) {
		case S_IFDIR:
		case S_IFREG:
			rfd->file_obj = reg_file_obj(path, flags, rfd);
			break;
		case S_IFIFO:
			rfd->file_obj = fifo_file_obj(path, flags, rfd);
		case S_IFSOCK:
		case S_IFLNK:
		case S_IFBLK:
		case S_IFCHR:
			return -ENOTSUP;
		default:
			pr_err("unknown file mode: 0%o\n", rfd->mode & S_IFMT);
			return -EINVAL;
	}
	return rfd->file_obj ? 0 : -EPERM;
}

static int get_link_path(const char *link, const char *mountpoint,
			 char *path, size_t size)
{
	ssize_t used, bytes;

	/* Why mountpoint is added in front of the path?
	 * Because spfs in unmounted already. And it means, that mount point
	 * was removed from the beginning of the path fd points to.
	 */
	snprintf(path, PATH_MAX, "%s", mountpoint);
	used = strlen(path);

	bytes = readlink(link, path + used, size - used - 1);
	if (bytes < 0) {
		pr_perror("failed to read link %s\n", link);
		return -errno;
	}
	path[used+bytes] = '\0';
	pr_debug("%s --> %s\n", link, path);
	return 0;
}

static int open_replace_fd(struct replace_fd *rfd, unsigned flags, const char *mountpoint)
{
	char link[PATH_MAX];
	char path[PATH_MAX];
	struct stat st;
	int err;

	snprintf(link, PATH_MAX, "/proc/%d/fd/%d", rfd->pid, rfd->spfs_fd);

	err = get_link_path(link, mountpoint, path, sizeof(path));
	if (err)
		return err;

	if (stat(path, &st)) {
		pr_perror("failed to stat %s", path);
		return -errno;
	}

	rfd->mode = st.st_mode;

	/* TODO it makes sense to open only shared files here.
	 * Private files can be opened by the process itself */

	return create_file_obj(path, flags, rfd);
}

static int get_replace_fd(struct replace_fd *rfd, unsigned flags, const char *mountpoint)
{
	int err;

	if (!rfd->file_obj) {
		err = open_replace_fd(rfd, flags, mountpoint);
		if (err) {
			pr_err("failed to open file object for /proc/%d/fd/%d\n",
					rfd->pid, rfd->spfs_fd);
			return err;
		}
	}

	switch (rfd->mode & S_IFMT) {
		case S_IFDIR:
		case S_IFREG:
			return (long)rfd->file_obj;
		case S_IFIFO:
		case S_IFSOCK:
		case S_IFLNK:
		case S_IFBLK:
		case S_IFCHR:
			break;
		default:
			pr_err("unknown file mode: 0%o\n", rfd->mode & S_IFMT);
			return -EINVAL;
	}
	return -ENOTSUP;
}


static int get_real_fd(pid_t pid, int fd, const char *mountpoint)
{
	int err;
	struct replace_fd *rfd;
	int flags;

	flags = get_fd_flags(pid, fd);
	if (flags < 0)
		return flags;

	err = add_fd_to_tree(pid, fd, &rfd);
	if (err) {
		pr_err("failed to add /proc/%d/fd/%d to tree\n", pid, fd);
		return err;
	}

	return get_replace_fd(rfd, flags, mountpoint);
}

static int process_add_fd(struct process_info *p, int spfs_fd, int real_fd)
{
	struct process_fd *pfd;

	pfd = malloc(sizeof(*pfd));
	if (!pfd) {
		pr_err("failed to allocate pfd\n");
		return -ENOMEM;
	}

	pfd->spfs_fd = spfs_fd;
	pfd->real_fd = real_fd;
	list_add_tail(&pfd->list, &p->fds);
	p->fds_nr++;

	pr_debug("Added replace fd: /proc/%d/fd/%d --> /proc/%d/fd/%d\n",
			getpid(), pfd->spfs_fd, p->pid, pfd->real_fd);
	return 0;
}

static int process_add_mapping(struct process_info *p, int map_fd,
				off_t start, off_t end)
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
	list_add_tail(&mfd->list, &p->maps);
	p->maps_nr++;

	pr_debug("Added replace mapping: /proc/%d/fd/%d (%lx-%lx)\n",
			getpid(), mfd->map_fd, mfd->start, mfd->end);
	return 0;
}

static int collect_process_fd(struct process_info *p, int dir,
			      const char *process_fd, const void *data)
{
	int err, source_fd, target_fd;
	const struct mount_info_s *mnt = data;

	if (!is_mnt_fd(dir, process_fd, mnt->st.st_dev))
		return 0;

	pr_debug("Collecting /proc/%d/fd/%s\n", p->pid, process_fd);

	err = xatol(process_fd, (long *)&source_fd);
	if (err) {
		pr_err("failed to convert fd %s to number\n", process_fd);
		return err;
	}

	target_fd = get_real_fd(p->pid, source_fd, mnt->mountpoint);
	if (target_fd < 0)
		return target_fd;

	return process_add_fd(p, source_fd, target_fd);
}

static int get_map_range(const char *map_file, off_t *start, off_t *end)
{
	int ret;

	ret = sscanf(map_file, "%lx-%lx", start, end);
	if (ret != 2) {
		pr_err("failed to parse map file %s\n", map_file);
		return -EINVAL;
	}
	return 0;
}

static int collect_map_fd(struct process_info *p, int dir,
			  const char *map_file, const void *data)
{
	char link[PATH_MAX];
	char path[PATH_MAX];
	off_t start, end;
	int map_fd, err;
	const struct mount_info_s *mnt = data;

	if (!is_mnt_fd(dir, map_file, mnt->st.st_dev))
		return 0;

	snprintf(link, PATH_MAX, "/proc/%d/map_files/%s", p->pid, map_file);

	pr_debug("Collecting %s\n", link);

	err = get_map_range(map_file, &start, &end);
	if (err)
		return err;

	err = get_link_path(link, mnt->mountpoint, path, sizeof(path));
	if (err)
		return err;

	map_fd = open(path, O_RDWR);
	if (map_fd < 0) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	return process_add_mapping(p, map_fd, start, end);
}

static int iterate_dir_name(const char *dpath, struct process_info *p,
		    int (*actor)(struct process_info *p, int dir, const char *fd, const void *data),
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
			pr_err("actor '%s' for %s/%s\n failed\n",
					actor_name, dpath, fd);
			break;
		}
	}

close_dir:
	closedir(fdir);
	return err;
}

static int collect_process_open_fds(struct process_info *p, const struct mount_info_s *mnt)
{
	char dpath[PATH_MAX];

	snprintf(dpath, PATH_MAX, "/proc/%d/fd", p->pid);
	return iterate_dir_name(dpath, p, collect_process_fd, mnt, "collect_process_fd");
}

static int collect_process_map_fds(struct process_info *p, const struct mount_info_s *mnt)
{
	char dpath[PATH_MAX];

	snprintf(dpath, PATH_MAX, "/proc/%d/map_files", p->pid);
	return iterate_dir_name(dpath, p, collect_map_fd, mnt, "collect_map_fd");
}

static int collect_process_env(struct process_info *p, const struct mount_info_s *mnt)
{
	int dir, err, *env = p->env_array;
	char path[PATH_MAX];
	char *env_vars[] = {
		"exe",
		"cwd",
		"root",
		NULL
	}, **var;

	snprintf(path, PATH_MAX, "/proc/%d", p->pid);
	dir = open(path, O_RDONLY | O_DIRECTORY);
	if (dir < 0) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	/* TODO: exec, root and cwd can be shared */

	var = env_vars;
	while(*var) {
		char *dentry = *var++;
		char link[PATH_MAX];

		if (!is_mnt_fd(dir, dentry, mnt->st.st_dev))
			continue;

		pr_debug("Collecting /proc/%d/%s\n", p->pid, dentry);

		snprintf(link, PATH_MAX, "/proc/%d/%s", p->pid, dentry);
		err = get_link_path(link, mnt->mountpoint, path, sizeof(path));
		if (err)
			break;

		*env = open(path, O_RDONLY);
		if (*env < 0) {
			pr_perror("failed to open %s", path);
			err = -errno;
			break;
		}
		env++;
	}

	close(dir);
	return err;
}

static int collect_one_process(pid_t pid, void *data, const void *filter)
{
	int err;
	struct process_info *p;
	struct list_head *collection = data;
	const struct mount_info_s *mnt = filter;

	p = malloc(sizeof(*p));
	if (!p) {
		pr_err("failed to allocate process\n");
		return -ENOMEM;
	}

	p->pid = pid;
	p->fds_nr = 0;
	p->maps_nr = 0;
	p->env.exe_fd = -1;
	p->env.cwd_fd = -1;
	p->env.root_fd = -1;
	INIT_LIST_HEAD(&p->fds);
	INIT_LIST_HEAD(&p->maps);

	err = collect_process_env(p, mnt);
	if (err)
		goto free_p;

	err = collect_process_open_fds(p, mnt);
	if (err)
		goto free_p;

	err = collect_process_map_fds(p, mnt);
	if (err)
		goto free_p;

	if ((p->fds_nr + p->maps_nr) == 0)
		goto free_p;

	err = attach_to_process(p);
	if (err)
		goto free_p;
	list_add_tail(&p->list, collection);
	pr_debug("collected process %d\n", pid);
	return 0;

free_p:
	free(p);
	return err;
}

int collect_processes(const char *pids, struct list_head *collection,
		      const struct mount_info_s *mnt)
{
	return iterate_pids_list(pids, collection, mnt, collect_one_process);
}
