#include <unistd.h>
#include <sys/syscall.h>
#include <search.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#include "include/list.h"
#include "include/log.h"

#include "fd_tree.h"

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

static void *fd_tree_root = NULL;

static int compare_fds(const void *a, const void *b)
{
	const struct replace_fd *f = a, *s = b;
	int ret;

	ret = syscall(SYS_kcmp, f->pid, s->pid, KCMP_FILE, f->fd, s->fd);

	switch (ret) {
		case 0:
			return 0;
		case 1:
			return -1;
		case 2:
			return 1;
	}

	if (ret < 0)
		pr_err("failed to compare /proc/%d/fd/%d with /proc/%d/fd/%d: %s\n",
			f->pid, f->fd, s->pid, s->fd, strerror(-ret));
	else
		pr_err("failed to compare /proc/%d/fd/%d with "
			"/proc/%d/fd/%d: ordering information is unavailable\n",
			f->pid, f->fd, s->pid, s->fd);
	_exit(EXIT_FAILURE);
}

int add_fd_to_tree(pid_t pid, int fd, struct replace_fd **rfd)
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
	new_fd->file_obj = NULL;

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
