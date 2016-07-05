#include <unistd.h>
#include <sys/syscall.h>
#include <search.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#include "include/list.h"
#include "include/log.h"

#include "trees.h"

enum kcmp_type {
	KCMP_FILE,
	KCMP_VM,
	KCMP_FILES,
	KCMP_FS,
	KCMP_SIGHAND,
	KCMP_IO,
	KCMP_SYSVSEM,

	KCMP_TYPES,
};

struct map_fd_s {
	int map_fd;
	char *path;
	mode_t mode;
};

struct fd_table_s {
	pid_t pid;
};

struct fs_struct_s {
	pid_t pid;
};

struct mm_struct_s {
	pid_t pid;
};

static void *fd_tree_root = NULL;
static void *fd_table_tree_root = NULL;
static void *fs_struct_tree_root = NULL;
static void *map_fd_tree_root = NULL;
static void *fifo_tree_root = NULL;
static void *mm_tree_root = NULL;

static void free_fd_node(void *nodep)
{
	struct replace_fd *rfd = nodep;
	/*TODO close file_obj somehow... */

	free(rfd);
}

static void free_fd_table_node(void *nodep)
{
	free(nodep);
}

static void free_fs_struct_node(void *nodep)
{
	free(nodep);
}

static void free_map_fd_node(void *nodep)
{
	struct map_fd_s *mfd = nodep;

	close(mfd->map_fd);
	free(mfd);
}

static void free_fifo_node(void *nodep)
{
	free(nodep);
}

static void free_mm_node(void *nodep)
{
	free(nodep);
}

void destroy_obj_trees(void)
{
	tdestroy(fd_tree_root, free_fd_node);
	tdestroy(fd_table_tree_root, free_fd_table_node);
	tdestroy(fs_struct_tree_root, free_fs_struct_node);
	tdestroy(map_fd_tree_root, free_map_fd_node);
	tdestroy(fifo_tree_root, free_fifo_node);
	tdestroy(mm_tree_root, free_mm_node);
}

static int kcmp(int type, pid_t pid1, pid_t pid2, unsigned long idx1, unsigned long idx2)
{
	int ret;

	ret = syscall(SYS_kcmp, pid1, pid2, type, idx1, idx2);

	switch (ret) {
		case 0:
			return 0;
		case 1:
			return -1;
		case 2:
			return 1;
		case -1:
			pr_perror("kcmp (type: %d, pid1: %d, pid2: %d, "
				  "idx1: %ld, idx2: %ld) failed",
				  type, pid1, pid2, idx1, idx2);
			break;
		default:
			pr_perror("kcmp (type: %d, pid1: %d, pid2: %d, "
				  "idx1: %ld, idx2: %ld) returned %d\n",
				  type, pid1, pid2, idx1, idx2);
			break;
	}
	_exit(EXIT_FAILURE);
}

static int compare_fds(const void *a, const void *b)
{
	const struct replace_fd *f = a, *s = b;

	return kcmp(KCMP_FILE, f->pid, s->pid, f->fd, s->fd);
}

int collect_fd(pid_t pid, int fd, void *file_obj, struct replace_fd **rfd)
{
	struct replace_fd *new_fd, **found_fd;
	int err = -ENOMEM;

	new_fd = malloc(sizeof(*new_fd));
	if (!new_fd) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}
	new_fd->pid = pid;
	new_fd->fd = fd;
	new_fd->shared = false;
	new_fd->file_obj = file_obj;

	found_fd = tsearch(new_fd, &fd_tree_root, compare_fds);
	if (!found_fd) {
		pr_err("failed to add new fd object to the tree\n");
		goto free_new_fd;
	}

	if (*found_fd != new_fd)
		(*found_fd)->shared = true;

	*rfd = *found_fd;
	err = 0;

free_new_fd:
	if (*found_fd != new_fd)
		free(new_fd);
	return err;
}

static int compare_fd_tables(const void *a, const void *b)
{
	const struct fd_table_s *f = a, *s = b;

	return kcmp(KCMP_FILES, f->pid, s->pid, 0, 0);
}

pid_t fd_table_exists(pid_t pid)
{
	struct fd_table_s fdt = {
		.pid = pid,
	}, **found_fdt;

	found_fdt = tfind(&fdt, &fd_table_tree_root, compare_fd_tables);
	if (!found_fdt)
		return 0;
	return (*found_fdt)->pid;
}

int collect_fd_table(pid_t pid)
{
	struct fd_table_s *new_fdt, **found_fdt;
	int err = -ENOMEM;

	new_fdt = malloc(sizeof(*new_fdt));
	if (!new_fdt) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}
	new_fdt->pid = pid;

	found_fdt = tsearch(new_fdt, &fd_table_tree_root, compare_fd_tables);
	if (!found_fdt) {
		pr_err("failed to add new fdt object to the tree\n");
		goto free_new_fdt;
	}

	if (*found_fdt == new_fdt)
		return 0;

	pr_info("process %d shares fd table with process %d\n", pid,
			(*found_fdt)->pid);

	err = -EEXIST;

free_new_fdt:
	free(new_fdt);
	return err;
}

static int compare_fs_struct(const void *a, const void *b)
{
	const struct fs_struct_s *f = a, *s = b;

	return kcmp(KCMP_FS, f->pid, s->pid, 0, 0);
}

pid_t fs_struct_exists(pid_t pid)
{
	struct fs_struct_s fs = {
		.pid = pid,
	}, **found_fs;

	found_fs = tfind(&fs, &fs_struct_tree_root, compare_fs_struct);
	if (!found_fs)
		return 0;
	return (*found_fs)->pid;
}

int collect_fs_struct(pid_t pid)
{
	struct fs_struct_s *new_fs, **found_fs;
	int err = -ENOMEM;

	new_fs = malloc(sizeof(*new_fs));
	if (!new_fs) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}
	new_fs->pid = pid;

	found_fs = tsearch(new_fs, &fs_struct_tree_root, compare_fs_struct);
	if (!found_fs) {
		pr_err("failed to add new fs object to the tree\n");
		goto free_new_fs;
	}

	if (*found_fs == new_fs)
		return 0;

	pr_info("process %d shares fs struct with process %d\n", pid,
			(*found_fs)->pid);
	err = -EEXIST;

free_new_fs:
	free(new_fs);
	return err;
}

static int compare_map_fd(const void *a, const void *b)
{
	const struct map_fd_s *f = a, *s = b;
	int ret;

	ret = strcmp(f->path, s->path);
	if (ret)
		return ret;
	if (f->mode < s->mode)
		return -1;
	else if (f->mode > s->mode)
		return 1;
	return 0;
}

int collect_map_fd(int fd, const char *path, mode_t mode, int *map_fd)
{
	struct map_fd_s *new_map_fd, **found_map_fd;
	int err = -ENOMEM;

	new_map_fd = malloc(sizeof(*new_map_fd));
	if (!new_map_fd) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}
	new_map_fd->path = strdup(path);
	if (!new_map_fd->path) {
		pr_err("failed to allocate\n");
		goto free_new_map_fd;
	}
	new_map_fd->map_fd = fd;
	new_map_fd->mode = mode;

	found_map_fd = tsearch(new_map_fd, &map_fd_tree_root, compare_map_fd);
	if (!found_map_fd) {
		pr_err("failed to add new map fd object to the tree\n");
		goto free_new_map_fd_map_fd;
	}

	*map_fd = (*found_map_fd)->map_fd;
	err = 0;

	if (*found_map_fd == new_map_fd)
		goto exit;

free_new_map_fd_map_fd:
	free(new_map_fd->path);
free_new_map_fd:
	free(new_map_fd);
exit:
	return err;
}

static int compare_paths(const void *a, const void *b)
{
	const char *f = a, *s = b;

	return strcmp(f, s);
}

static int collect_path(const char *path, void **root)
{
	char *p;
	const char **fp;

	p = strdup(path);
	if (!p) {
		pr_err("failed to duplicate string\n");
		free(p);
		return -ENOMEM;
	}

	fp = tsearch(p, root, compare_paths);
	if (!fp) {
		pr_err("failed to add new path object to the tree\n");
		return -ENOMEM;
	}

	if (*fp == p)
		return 0;

	return -EEXIST;
}

int collect_fifo(const char *path)
{
	return collect_path(path, &fifo_tree_root);
}

static int compare_mm_struct(const void *a, const void *b)
{
	const struct mm_struct_s *f = a, *s = b;

	return kcmp(KCMP_VM, f->pid, s->pid, 0, 0);
}

pid_t mm_exists(pid_t pid)
{
	struct mm_struct_s mm = {
		.pid = pid,
	}, **found_mm;


	found_mm = tfind(&mm, &mm_tree_root, compare_mm_struct);
	if (!found_mm)
		return 0;
	return (*found_mm)->pid;
}

int collect_mm(pid_t pid)
{
	struct mm_struct_s *new_mm, **found_mm;
	int err = -ENOMEM;

	new_mm = malloc(sizeof(*new_mm));
	if (!new_mm) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}
	new_mm->pid = pid;

	found_mm = tsearch(new_mm, &mm_tree_root, compare_mm_struct);
	if (!found_mm) {
		pr_err("failed to add new mm object to the tree\n");
		goto free_new_mm;
	}

	if (*found_mm == new_mm)
		return 0;

	pr_info("process %d shares mm struct with process %d\n", pid,
			(*found_mm)->pid);
	err = -EEXIST;

free_new_mm:
	free(new_mm);
	return err;
}
