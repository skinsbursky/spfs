#ifndef __SPFS_MANAGER_SWAPFD_H__
#define __SPFS_MANAGER_SWAPFD_H__

struct swapfd_exchange {
	pid_t		pid;

	unsigned long 	*addr;		/* Array of starts of mappings, which be re-backed by addr_fd */
	int		*addr_fd;
	int		naddr;		/* Number of re-backed mappings */

	int		*src_fd;	/* Array of tracee's fds to be replaced with caller's dst_fds */
	int		*dst_fd;
	int		nfd;		/* Number of replaced fds */

	int		exe_fd;		/* exe fd or -1 */
	int		cwd_fd;		/* cwd fd or -1 */
};

pid_t attach_to_task(pid_t pid);
int detach_from_task(pid_t pid);
int wait_task_seized(pid_t pid);
int swapfd_tracee(struct swapfd_exchange *se);

#endif
