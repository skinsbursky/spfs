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

static int do_swap_process_resources(struct process_info *p)
{
	struct process_fd *pfd;
	struct process_map *mfd;
	int err = -ENOMEM;
	struct swapfd_exchange se = {
		.exe_fd = -1,
		.cwd_fd = -1,
	};

	pr_debug("Swapping process %d resources:\n", p->pid);

	if (p->fds_nr) {
		int *s, *d;
		unsigned long *f;

		se.src_fd = malloc(sizeof(*se.src_fd) * p->fds_nr);
		se.dst_fd = malloc(sizeof(*se.dst_fd) * p->fds_nr);
		se.setfd = malloc(sizeof(*se.setfd) * p->fds_nr);
		if (!se.src_fd || !se.dst_fd || !se.setfd) {
			pr_err("failed to allocate\n");
			goto free;
		}

		s = se.src_fd;
		d = se.dst_fd;
		f = se.setfd;
		list_for_each_entry(pfd, &p->fds, list) {
			pr_debug("\t/proc/%d/fd/%d --> /proc/%d/fd/%d %s\n",
					getpid(), pfd->target_fd,
					p->pid, pfd->source_fd,
					pfd->cloexec ? "(O_CLOEXEC)" : "");
			*s++ = pfd->source_fd;
			*d++ = pfd->target_fd;
			*f++ = pfd->cloexec;
		}
		se.nfd = p->fds_nr;
	}

	if (p->maps_nr) {
		int *m;
		unsigned long *ma;

		se.addr = malloc(sizeof(*se.addr) * p->maps_nr);
		se.addr_fd = malloc(sizeof(*se.addr_fd) * p->maps_nr);
		if (!se.addr || !se.addr) {
			pr_err("failed to allocate\n");
			goto free;
		}

		m = se.addr_fd;
		ma = se.addr;
		list_for_each_entry(mfd, &p->maps, list) {
			pr_debug("\t/proc/%d/fd/%d --> /proc/%d/map_files/%ld-%ld\n",
					getpid(), mfd->map_fd, p->pid, mfd->start, mfd->end);
			*m++ = mfd->map_fd;
			*ma++ = mfd->start;
		}
		se.naddr = p->maps_nr;
	}

	if (p->exe_fd >= 0) {
		pr_debug("\t/proc/%d/fd/%d --> /proc/%d/exe\n",
				getpid(), p->exe_fd, p->pid);
		se.exe_fd = p->exe_fd;
	}

	if (p->fs.cwd_fd >= 0) {
		pr_debug("\t/proc/%d/fd/%d --> /proc/%d/cwd\n",
				getpid(), p->fs.cwd_fd, p->pid);
		se.cwd_fd = p->fs.cwd_fd;
	}

	if (p->fs.root) {
		pr_debug("\t%s --> /proc/%d/root\n", p->fs.root, p->pid);
		se.root.cwd_fd = open("/", O_PATH);
		if (se.root.cwd_fd < 0) {
			pr_perror("failed to open /");
			goto free;
		}
		se.root.path = p->fs.root + 1;
	}

	se.pid = p->pid;

	err = swapfd_tracee(p->pctl, &se);

	close(se.root.cwd_fd);
free:
	free(se.setfd);
	free(se.src_fd);
	free(se.dst_fd);
	free(se.addr);
	free(se.addr_fd);
	return err;
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
