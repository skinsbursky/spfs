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

int set_namespaces(int *ns_fds, bool close_fds)
{
	int ns_type, err;

	for (ns_type = NS_UTS; ns_type < NS_MAX; ns_type++) {
		if (ns_fds[ns_type] < 0)
			continue;

		err = setns(ns_fds[ns_type], 0);
		if (err) {
			pr_perror("failed to set ns by fd %d", ns_fds[ns_type]);
			break;
		}

		if (close_fds) {
			close(ns_fds[ns_type]);
			ns_fds[ns_type] = -1;
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

int def_namespaces(const char *namespaces, bool *ns_req)
{
	char *ns_list, *ns;
	int err = 0, ns_type;

	ns_list = strdup(namespaces);
	if (!ns_list) {
		pr_err("failed to duplicate namespaces\n");
		return -ENOMEM;
	}

	while ((ns = strsep(&ns_list, ",")) != NULL) {
		if (!strcmp(ns, "uts"))
			ns_type = NS_UTS;
		else if (!strcmp(ns, "mnt"))
			ns_type = NS_MNT;
		else if (!strcmp(ns, "net"))
			ns_type = NS_NET;
		else if (!strcmp(ns, "pid"))
			ns_type = NS_PID;
		else if (!strcmp(ns, "user"))
			ns_type = NS_USER;
		else {
			pr_err("unknown namespace: %s\n", ns);
			err = -EINVAL;
			break;
		}
		ns_req[ns_type] = true;
	}
	free(ns_list);
	return err;
}

char *ns_names[NS_MAX] = {
	"uts", "mnt", "net", "pid", "user",
};

int open_namespaces(pid_t pid, const char *namespaces, int *ns_fds)
{
	int err = 0, ns_type;
	bool ns_req[NS_MAX] = {
		false, false, false, false, false
	};

	err = def_namespaces(namespaces, ns_req);
	if (err)
		return err;

	for (ns_type = NS_UTS; ns_type < NS_MAX; ns_type++) {
		if (ns_req[ns_type] == false) {
			ns_fds[ns_type] = -1;
			continue;
		}

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

int change_namespaces(pid_t pid, const char *namespaces, int *fds[])
{
	int ns_fds[NS_MAX] = {
		-1, -1, -1, -1, -1
	};
	int err;

	err = open_namespaces(pid, namespaces, ns_fds);
	if (err)
		return err;

	err = set_namespaces(ns_fds, true);

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

int spfs_seize_processes(struct spfs_info_s *info)
{
	const struct process_info *p;

	list_for_each_entry(p, &info->processes, list) {
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

int spfs_release_processes(struct spfs_info_s *info)
{
	struct process_info *p, *tmp;

	list_for_each_entry_safe(p, tmp, &info->processes, list) {
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

static bool is_spfs_fd(int dir, const char *fd, struct spfs_info_s *info)
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
	if (st.st_dev != info->spfs_stat.st_dev)
		return false;

	return true;
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

int iterate_pids_list_name(const char *pids_list, struct spfs_info_s *info,
			   int (*actor)(pid_t pid, struct spfs_info_s *info),
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

		err = actor(p, info);
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

static int open_replace_fd(struct replace_fd *rfd, unsigned flags, const char *mountpoint)
{
	char path[PATH_MAX];
	char link[PATH_MAX];
	ssize_t used, bytes;
	struct stat st;

	/* TODO it makes sense to open only shared files here.
	 * Private files can be opened by the process itself */

	snprintf(link, PATH_MAX, "/proc/%d/fd/%d", rfd->pid, rfd->spfs_fd);

	if (stat(link, &st)) {
		pr_err("failed to stat %s", link);
		return -errno;
	}

	rfd->mode = st.st_mode;

	/* Why mountpoint is added in front of the path?
	 * Because spfs in unmounted already. And it means, that mount point
	 * was removed from the beginning of the path fd points to.
	 */
	snprintf(path, PATH_MAX, "%s", mountpoint);
	used = strlen(path);

	bytes = readlink(link, path + used, sizeof(path) - used);
	if (bytes < 0) {
		pr_perror("failed to read link %s\n", link);
		return -errno;
	}
	path[used+bytes] = '\0';

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

static int collect_process_fd(struct process_info *p, int dir, const char *process_fd)
{
	int err, spfs_fd, real_fd;
	struct spfs_info_s *info = p->info;
	struct process_fd *pfd;

	if (!is_spfs_fd(dir, process_fd, info))
		return 0;

	pr_debug("Collecting /proc/%d/fd/%s\n", p->pid, process_fd);

	err = xatol(process_fd, (long *)&spfs_fd);
	if (err) {
		pr_err("failed to convert fd %s to number\n", process_fd);
		return err;
	}

	real_fd = get_real_fd(p->pid, spfs_fd, info->mountpoint);
	if (real_fd < 0)
		return real_fd;

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


static int iterate_process_fds_name(struct process_info *p,
		    int (*actor)(struct process_info *p, int dir, const char *fd),
		    const char *actor_name)
{
	char dpath[PATH_MAX];
	struct dirent *dt;
	DIR *fdir;
	int dir;
	int err;

	snprintf(dpath, PATH_MAX, "/proc/%d/fd", p->pid);
	fdir = opendir(dpath);
	if (!fdir) {
		pr_perror("failed to open %s", dpath);
		return -errno;
	}

	dir = dirfd(fdir);
	if (dir < 0) {
		pr_perror("failed to get fd for %s stream", dpath);
		err = -errno;
		goto close_fdir;
	}

        while ((dt = readdir(fdir)) != NULL) {
		char *fd = dt->d_name;

		if (!strcmp(fd, ".") || !strcmp(fd, ".."))
			continue;

		err = actor(p, dir, fd);
		if (err) {
			pr_err("actor '%s' for /proc/%d/fd/%s\n failed\n",
					actor_name, p->pid, fd);
			break;
		}
	}

close_fdir:
	closedir(fdir);
	return err;
}

int collect_one_process(pid_t pid, struct spfs_info_s *info)
{
	int err;
	struct process_info *p;

	p = malloc(sizeof(*p));
	if (!p) {
		pr_err("failed to allocate process\n");
		return -ENOMEM;
	}

	p->pid = pid;
	p->info = info;
	p->fds_nr = 0;
	INIT_LIST_HEAD(&p->fds);

	err = iterate_process_fds_name(p, collect_process_fd, "collect_process_fd");
	if (err)
		return err;

	if (p->fds_nr == 0)
		goto free_p;

	err = attach_to_process(p);
	if (err)
		goto free_p;
	list_add_tail(&p->list, &info->processes);
	pr_debug("collected process %d\n", pid);
	return 0;

free_p:
	free(p);
	return err;
}

