#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <signal.h>

#include "include/util.h"
#include "include/log.h"
#include "include/socket.h"
#include "include/shm.h"

#include "spfs/context.h"

#include "context.h"
#include "interface.h"
#include "replace.h"
#include "spfs.h"
#include "freeze.h"
#include "swap.h"
#include "swapfd.h"
#include "processes.h"
#include "cgroup.h"

static int do_replace_resources(struct freeze_cgroup_s *fg,
				const char *source_mnt,
				dev_t src_dev,
				const char *target_mnt,
				int *ns_fds)
{
	char *pids;
	int err;
	int freezer_state_fd;
	LIST_HEAD(processes);

	freezer_state_fd = open_cgroup_state(fg);
	if (freezer_state_fd < 0)
		return freezer_state_fd;

	err = cgroup_pids(fg, &pids);
	if (err)
		return err;

	/* Set target mount and network namespaces to be able to collect opened
	 * files and file mapping information.
	 * Important: we do not change user namespace here, because
	 * /proc/<pid>/map_files won't be accessible.
	 */
	err = set_namespaces(ns_fds, NS_MNT_MASK | NS_NET_MASK);
	if (err)
		goto free_pids;

	if (source_mnt)
		err = collect_mnt_processes(pids, &processes,
					    source_mnt, target_mnt);
	else
		err = collect_dev_processes(pids, &processes,
					    src_dev, target_mnt);
	if (err)
		goto free_pids;

#if 0
	Looks like user namespace is not required at all?
	err = set_namespaces(ns_fds, NS_USER_MASK);
	if (err)
		goto free_pids;
#endif

	err = write(freezer_state_fd, "THAWED", sizeof("THAWED"));
	if (err != sizeof("THAWED")) {
		pr_perror("Unable to thaw");
		goto free_pids;
	}
	close(freezer_state_fd);

	err = seize_processes(&processes);
	if (err)
		goto free_pids;

	err = do_swap_resources(&processes);
	if (err)
		goto free_pids;

	err = release_processes(&processes);

free_pids:
	free(pids);
	return err;
}

int replace_resources(struct freeze_cgroup_s *fg,
		      const char *source_mnt, dev_t src_dev,
		      const char *target_mnt,
		      pid_t ns_pid)
{
	int err, status, pid;
	int ct_ns_fds[NS_MAX];

	err = open_namespaces(ns_pid, ct_ns_fds);
	if (err) {
		pr_perror("failed to open %d namespaces\n", ns_pid);
		return err;
	}

	/* Join target pid namespace to extract virtual pids from freezer cgroup.
	 * This is required, because resources reopen must be performed in
	 * container's context (correct /proc is needed for different checks
	 * and opened file modifications).
	 * Also, ptrace needs to use pids, located in its pid namespace.
	 */
	err = set_namespaces(ct_ns_fds, NS_PID_MASK);
	if (err)
		goto close_namespaces;

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			err = -errno;
		case 0:
			_exit(do_replace_resources(fg, source_mnt, src_dev,
						   target_mnt, ct_ns_fds));
	}

	if (pid > 0)
		err = collect_child(pid, &status, 0);

close_namespaces:
	close_namespaces(ct_ns_fds);
	return err ? err : status;
}
