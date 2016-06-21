#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <stdbool.h>

#include "include/log.h"
#include "include/util.h"

#include "swap.h"
#include "processes.h"
#include "swapfd.h"

typedef enum swap_resource_type {
	SWAP_RESOURCE_FDS,
	SWAP_RESOURCE_MAP,
	SWAP_RESOURCE_FS,
	SWAP_RESOURCE_EXE,
	SWAP_RESOURCE_MAX,
} swap_resource_t;

static int do_swap_process_fds(struct process_info *p)
{
	struct process_fd *pfd;
	int err = -ENOMEM;
	int *src_fd, *dst_fd, *s, *d;
	unsigned long *cloexec, *ce;

	if (!p->fds_nr)
		return 0;

	pr_debug("Swapping process %d file descriptors:\n", p->pid);

	src_fd = s = malloc(sizeof(int) * p->fds_nr);
	dst_fd = d = malloc(sizeof(int) * p->fds_nr);
	cloexec = ce = malloc(sizeof(unsigned long) * p->fds_nr);
	if (!src_fd || !dst_fd || !cloexec) {
		pr_err("failed to allocate\n");
		goto free;
	}

	list_for_each_entry(pfd, &p->fds, list) {
		pr_debug("\t/proc/%d/fd/%d --> /proc/%d/fd/%d %s\n",
				getpid(), pfd->target_fd,
				p->pid, pfd->source_fd,
				pfd->cloexec ? "(O_CLOEXEC)" : "");
		*s++ = pfd->source_fd;
		*d++ = pfd->target_fd;
		*ce++ = pfd->cloexec;
	}

	err = swap_fds(p->pctl, src_fd, dst_fd, cloexec, p->fds_nr);

free:
	free(cloexec);
	free(dst_fd);
	free(src_fd);
	return err;
}

static int do_swap_process_maps(struct process_info *p)
{
	struct process_map *pm;
	int err = -ENOMEM;
	int *map_fds, *mfd;
	unsigned long *map_addrs, *maddr;

	if (!p->maps_nr)
		return 0;

	pr_debug("Swapping process %d mappings:\n", p->pid);

	map_fds = mfd = malloc(sizeof(int) * p->maps_nr);
	map_addrs = maddr = malloc(sizeof(unsigned long) * p->maps_nr);
	if (!map_fds || !map_addrs) {
		pr_err("failed to allocate\n");
		goto free;
	}

	list_for_each_entry(pm, &p->maps, list) {
		pr_debug("\t/proc/%d/fd/%d --> /proc/%d/map_files/%ld-%ld\n",
				getpid(), pm->map_fd, p->pid, pm->start, pm->end);
		*mfd++ = pm->map_fd;
		*maddr++ = pm->start;
	}

	err = swap_maps(p->pctl, map_addrs, map_fds, p->maps_nr);

free:
	free(map_addrs);
	free(map_fds);
	return err;
}

static int do_swap_process_fs(struct process_info *p)
{
	int err;
	int cwd_fd = -1;

	if ((p->fs.cwd_fd < 0) && !p->fs.root < 0)
		return 0;

	pr_debug("Swapping process %d fs:\n", p->pid);


	if (p->fs.root) {
		pr_debug("\t%s --> /proc/%d/root\n", p->fs.root, p->pid);
		cwd_fd = open("/", O_PATH);
		if (cwd_fd < 0) {
			pr_perror("failed to open /");
			return -errno;
		}

		err = swap_root(p->pctl, cwd_fd, p->fs.root + 1, p->fs.cwd_fd == -1);
		if (err)
			goto err;
	}

	if (p->fs.cwd_fd) {
		pr_debug("\t/proc/%d/fd/%d --> /proc/%d/cwd\n",
				getpid(), p->fs.cwd_fd, p->pid);
		err = swap_cwd(p->pctl, p->fs.cwd_fd);
		if (err)
			goto err;
	}

err:
	if (cwd_fd >= 0)
		close(cwd_fd);
	return err;
}

static int do_swap_process_exe(struct process_info *p)
{
	if (p->exe_fd < 0)
		return 0;

	pr_debug("Swapping process %d exe:\n", p->pid);

	pr_debug("\t/proc/%d/fd/%d --> /proc/%d/exe\n",
			getpid(), p->exe_fd, p->pid);

	return swap_exe(p->pctl, p->exe_fd);
}

typedef int (*swap_handler_t)(struct process_info *p);

static swap_handler_t swap_resources_handlers[SWAP_RESOURCE_MAX] = {
	[SWAP_RESOURCE_FDS] = do_swap_process_fds,
	[SWAP_RESOURCE_MAP]  = do_swap_process_maps,
	[SWAP_RESOURCE_FS] = do_swap_process_fs,
	[SWAP_RESOURCE_EXE] = do_swap_process_exe,
};

static swap_handler_t get_swap_handler(swap_resource_t type)
{
	if ((type >= SWAP_RESOURCE_MAX) || (type < SWAP_RESOURCE_FDS)) {
		pr_perror("invalid swap resource type: %d\n", type);
		return NULL;
	}
	return swap_resources_handlers[type];
}

static int do_swap_process_resources(struct process_info *p)
{
	swap_resource_t type;

	pr_debug("Swapping process %d resources:\n", p->pid);

	for (type = SWAP_RESOURCE_FDS; type < SWAP_RESOURCE_MAX; type++) {
		swap_handler_t handler;
		int err;

		handler = get_swap_handler(type);
		if (handler < 0)
			return -EINVAL;

		err = handler(p);
		if (err)
			return err;
	}
	return 0;
}

static bool process_needs_swap(struct process_info *p)
{
	if (p->fds_nr)
		return true;
	if (p->maps_nr)
		return true;
	if (p->exe_fd != -1)
		return true;
	if (p->fs.cwd_fd != -1)
		return true;
	if (p->fs.root)
		return true;
	return false;
}

int do_swap_resources(const struct list_head *processes)
{
	struct process_info *p;

	pr_debug("Swapping resources:\n");

	list_for_each_entry(p, processes, list) {
		if (!process_needs_swap(p))
			continue;
		if (do_swap_process_resources(p))
			pr_err("failed to swap resources for process %d\n", p->pid);
	}

	return 0;
}
