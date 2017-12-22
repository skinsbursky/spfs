#include "spfs_config.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "include/util.h"
#include "include/log.h"
#include "include/namespaces.h"

#include "replace.h"
#include "freeze.h"
#include "swap.h"
#include "processes.h"
#include "context.h"
#include "unix-sockets.h"

static int do_replace_resources(struct freeze_cgroup_s *fg,
				struct replace_info_s *ri,
				int *ns_fds)
{
	char *pids;
	int err;
	LIST_HEAD(processes);
	unsigned orig_ns_mask;

	err = cgroup_pids(fg, &pids);
	if (err)
		return err;

	/* We need to set target mount namespace, because we need /proc, where
	 * we can check, whether process being collected is kthread or not.
	 */
	err = join_namespaces(ns_fds, NS_MNT_MASK, &orig_ns_mask);
	if (err)
		goto free_pids;

	err = collect_processes(pids, &processes);
	if (err)
		goto release_processes;

	/* And we also want to revert mount namespace back, so we can find the
	 * freezer cgroup to thaw before seize. */
	err = set_namespaces(mgr_ns_fds(), orig_ns_mask);
	if (err)
		goto release_processes;

	err = thaw_cgroup(fg);
	if (err)
		goto release_processes;

	/* Set target mount back again, so we can examine processes files.
	 * We do it before seize, becuase of parasite injection, which accesses
	 * process /proc information.
	 */
	err = join_namespaces(ns_fds, NS_MNT_MASK | NS_NET_MASK, &orig_ns_mask);
	if (err)
		goto release_processes;

	err = seize_processes(&processes);
	if (err)
		goto release_processes;

	err = collect_unix_sockets(ri);
	if (err)
		goto release_processes;

	err = examine_processes(&processes, ri);
	if (err)
		goto release_processes;

	err = do_swap_resources(&processes);

release_processes:
	release_processes(&processes);
free_pids:
	free(pids);
	return err;
}

int __replace_resources(struct freeze_cgroup_s *fg, int *ns_fds,
		      const char *source_mnt, dev_t src_dev,
		      int src_mnt_ref, int src_mnt_id,
		      const char *target_mnt)
{
	int err, status = 0, pid;
	struct replace_info_s ri = {
		.src_dev = src_dev,
		.src_mnt_ref = src_mnt_ref,
		.src_mnt_id = src_mnt_id,
		.source_mnt = source_mnt,
		.target_mnt = target_mnt,
	};

	/* Join target pid namespace to extract virtual pids from freezer cgroup.
	 * This is required, because resources reopen must be performed in
	 * container's context (correct /proc is needed for different checks
	 * and opened file modifications).
	 * Also, ptrace needs to use pids, located in its pid namespace.
	 */
	err = join_namespaces(ns_fds, NS_PID_MASK, NULL);
	if (err)
		return err;

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			err = -errno;
			break;
		case 0:
			_exit(do_replace_resources(fg, &ri, ns_fds));
		default:
			err = collect_child(pid, &status, 0);
	}

	return err ? err : status;
}

int replace_resources(struct freeze_cgroup_s *fg,
		      const char *source_mnt, dev_t src_dev,
		      const char *target_mnt,
		      pid_t ns_pid)
{
	int res = 0, err, src_mnt_ref = -1, src_mnt_id = -1;
	int ct_ns_fds[NS_MAX], *ns_fds = NULL;

	if (ns_pid) {
		err = open_namespaces(ns_pid, ct_ns_fds);
		if (err) {
			pr_perror("failed to open %d namespaces", ns_pid);
			return err;
		}
		ns_fds = ct_ns_fds;
	}

	if (source_mnt) {
		src_mnt_ref = open(source_mnt, O_PATH);
		if (src_mnt_ref < 0) {
			err = -errno;
			pr_perror("failed to open %s", source_mnt);
			goto close_ns_fds;
		}

		src_mnt_id = pid_fd_mnt_id(getpid(), src_mnt_ref);
		if (src_mnt_id < 0) {
			pr_err("failed to %s mount ID: %d\n",
					source_mnt, src_mnt_id);
			err = src_mnt_id;
			goto close_ns_fds;
		}
	}

	err = lock_cgroup(fg);
	if (err)
		goto close_mnt_ref;

	err = freeze_cgroup(fg);
	if (err)
		goto unlock_cgroup;

	err = __replace_resources(fg, ns_fds, source_mnt, src_dev,
				  src_mnt_ref, src_mnt_id,
				  target_mnt);

	res = thaw_cgroup(fg);

unlock_cgroup:
	(void) unlock_cgroup(fg);
close_mnt_ref:
	if (src_mnt_ref != -1)
		close(src_mnt_ref);
close_ns_fds:
	if (ns_fds)
		close_namespaces(ns_fds);
	return err ? err : res;
}
