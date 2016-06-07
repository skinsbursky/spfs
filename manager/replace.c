#include <stdlib.h>

#include "include/util.h"
#include "include/log.h"
#include "include/namespaces.h"

#include "replace.h"
#include "freeze.h"
#include "swap.h"
#include "processes.h"

static int do_replace_resources(struct freeze_cgroup_s *fg,
				const char *source_mnt,
				dev_t src_dev,
				const char *target_mnt,
				int *ns_fds)
{
	char *pids;
	int err, ret;
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

	err = collect_processes(pids, &processes);
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
		goto release_processes;
	}
	close(freezer_state_fd);

	err = seize_processes(&processes);
	if (err)
		goto release_processes;

	if (source_mnt)
		err = examine_processes_by_mnt(&processes,
					       source_mnt, target_mnt);
	else
		err = examine_processes_by_dev(&processes,
					       src_dev, target_mnt);
	if (err)
		goto release_processes;

	err = do_swap_resources(&processes);

release_processes:
	ret = release_processes(&processes);
free_pids:
	free(pids);
	return err ? err : ret;
}

int __replace_resources(struct freeze_cgroup_s *fg,
		      const char *source_mnt, dev_t src_dev,
		      const char *target_mnt,
		      pid_t ns_pid)
{
	int err, status, pid;
	int ct_ns_fds[NS_MAX], *ns_fds = NULL;

	if (ns_pid) {
		err = open_namespaces(ns_pid, ct_ns_fds);
		if (err) {
			pr_perror("failed to open %d namespaces", ns_pid);
			return err;
		}
		ns_fds = ct_ns_fds;
	}

	/* Join target pid namespace to extract virtual pids from freezer cgroup.
	 * This is required, because resources reopen must be performed in
	 * container's context (correct /proc is needed for different checks
	 * and opened file modifications).
	 * Also, ptrace needs to use pids, located in its pid namespace.
	 */
	err = set_namespaces(ns_fds, NS_PID_MASK);
	if (err)
		goto close_namespaces;

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			err = -errno;
		case 0:
			_exit(do_replace_resources(fg, source_mnt, src_dev,
						   target_mnt, ns_fds));
	}

	if (pid > 0)
		err = collect_child(pid, &status, 0);

close_namespaces:
	close_namespaces(ns_fds);
	return err ? err : status;
}

int replace_resources(struct freeze_cgroup_s *fg,
		      const char *source_mnt, dev_t src_dev,
		      const char *target_mnt,
		      pid_t ns_pid)
{
	int res, err;

	res = lock_cgroup(fg);
	if (!res) {
		res = freeze_cgroup(fg);
		if (res)
			(void) unlock_cgroup(fg);
	}
	if (res)
		return res;

	err = __replace_resources(fg, source_mnt, src_dev, target_mnt, ns_pid);

	res = thaw_cgroup(fg);
	if (!res)
		(void) unlock_cgroup(fg);

	return err ? err : res;

}
