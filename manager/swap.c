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
#include "file_obj.h"

typedef enum swap_resource_type {
	SWAP_RESOURCE_FDS,
	SWAP_RESOURCE_MAP,
	SWAP_RESOURCE_FS,
	SWAP_RESOURCE_EXE,
	SWAP_RESOURCE_MAX,
} swap_resource_t;

static int do_swap_resource(const struct process_info *p, struct process_resource *res,
			    const void *data,
			    int (*cb)(const struct process_info *p,
				      int target_fd,
				      const void *data))
{
	int target_fd, err;

	target_fd = get_fobj_fd(res->fobj);
	if (target_fd < 0)
		return target_fd;

	err = cb(p, target_fd, data);
	if (err)
		return err;

	res->replaced = true;
	return 0;
}

static int do_swap_fd(const struct process_info *p, int target_fd, const void *data)
{
	const struct fd_info *info = data;

	pr_debug("    /proc/%d/fd/%d --> /proc/%d/fd/%d (%s%lli)\n",
			getpid(), target_fd,
			p->pid, info->source_fd,
			info->cloexec ? "O_CLOEXEC, " : "", info->pos);

	return swap_fd(p->pctl, info->source_fd, target_fd,
		       info->cloexec, info->pos);
}

static int do_swap_process_fds(struct process_info *p)
{
	struct process_fd *pfd, *tmp;
	int err;

	if (!p->fds_nr)
		return 0;

	pr_debug("Swapping process %d file descriptors:\n", p->pid);

	list_for_each_entry_safe(pfd, tmp, &p->fds, list) {
		err = do_swap_resource(p, &pfd->res, &pfd->info, do_swap_fd);
		if (err)
			return err;
		release_file_obj(pfd->res.fobj);
	}
	return 0;
}

static int do_swap_map(const struct process_info *p, int target_fd, const void *data)
{
	const struct map_info *info = data;

	pr_debug("    /proc/%d/fd/%d --> /proc/%d/map_files/%lx-%lx\n",
			getpid(), target_fd, p->pid, info->start, info->end);

	return swap_map(p->pctl, target_fd, info->start, info->end,
			info->prot, info->flags, info->pgoff);
}

static int do_swap_process_maps(struct process_info *p)
{
	struct process_map *pm;
	int err;

	if (!p->maps_nr)
		return 0;

	pr_debug("Swapping process %d mappings:\n", p->pid);

	list_for_each_entry(pm, &p->maps, list) {
		err = do_swap_resource(p, &pm->res, &pm->info, do_swap_map);
		if (err)
			return err;
		release_file_obj(pm->res.fobj);
	}

	return 0;
}

static int do_swap_process_fs(struct process_info *p)
{
	int err;
	int cwd_fd = -1;

	if ((p->fs.cwd_fd < 0) && !p->fs.root)
		return 0;

	pr_debug("Swapping process %d fs:\n", p->pid);


	if (p->fs.root) {
		pr_debug("    %s --> /proc/%d/root\n", p->fs.root, p->pid);
		cwd_fd = open("/", O_PATH);
		if (cwd_fd < 0) {
			pr_perror("failed to open /");
			return -errno;
		}

		err = swap_root(p->pctl, cwd_fd, p->fs.root + 1, p->fs.cwd_fd == -1);
		if (err)
			goto err;
	}

	if (p->fs.cwd_fd >= 0) {
		pr_debug("    /proc/%d/fd/%d --> /proc/%d/cwd\n",
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

	pr_debug("    /proc/%d/fd/%d --> /proc/%d/exe\n",
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

static int process_do_swap_handler(struct process_info *p, swap_resource_t type)
{
	swap_handler_t handler;

	handler = get_swap_handler(type);
	if (handler < 0)
		return -EINVAL;

	return handler(p);
}

static int process_do_swap_handlers(struct process_info *p,
				    swap_resource_t start,
				    swap_resource_t end)
{
	swap_resource_t type;

	for (type = start; type < end; type++) {
		int err;

		err = process_do_swap_handler(p, type);
		if (err)
			return err;
	}
	return 0;
}

static int do_swap_process_resources(struct process_info *p)
{
	pr_info("Swapping process %d resources\n", p->pid);

	return process_do_swap_handlers(p, SWAP_RESOURCE_FDS, SWAP_RESOURCE_EXE);
}

static int do_swap_exe_resources(struct process_info *p)
{
	return process_do_swap_handler(p, SWAP_RESOURCE_EXE);
}

static bool process_needs_resources_swap(struct process_info *p)
{
	if (p->fds_nr)
		return true;
	if (p->maps_nr)
		return true;
	if (p->fs.cwd_fd != -1)
		return true;
	if (p->fs.root)
		return true;
	return false;
}

static bool process_needs_exe_swap(struct process_info *p)
{
	return (p->exe_fd == -1) ? false : true;
}

int do_swap_resources(const struct list_head *processes)
{
	struct process_info *p;

	pr_debug("Swapping resources:\n");

	list_for_each_entry(p, processes, list) {
		if (!process_needs_resources_swap(p))
			continue;
		if (do_swap_process_resources(p))
			pr_err("failed to swap resources for process %d\n", p->pid);
	}

	list_for_each_entry(p, processes, list) {
		if (!process_needs_exe_swap(p))
			continue;
		if (do_swap_exe_resources(p))
			pr_err("failed to swap exe for process %d\n", p->pid);
	}

	return 0;
}
