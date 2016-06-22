#ifndef __SPFS_MANAGER_SWAPFD_H__
#define __SPFS_MANAGER_SWAPFD_H__

#include <stdbool.h>

struct swapfd_exchange {
	pid_t		pid;

	unsigned long 	*addr;		/* Array of starts of mappings, which be re-backed by addr_fd */
	int		*addr_fd;
	int		naddr;		/* Number of re-backed mappings */

	int		*src_fd;	/* Array of tracee's fds to be replaced with caller's dst_fds */
	int		*dst_fd;
	unsigned long	*setfd;		/* Arguments of F_SETFD */
	int		nfd;		/* Number of replaced fds */

	int		exe_fd;		/* exe fd or -1 */
	struct {
		int		cwd_fd;	/* cwd fd or -1 */
		char		*path;	/* path for chroot */
	} root;
	int		cwd_fd;		/* cwd fd or -1 */
};

struct parasite_ctl;

pid_t attach_to_task(pid_t pid);
int detach_from_task(pid_t pid);
int wait_task_seized(pid_t pid);
int swapfd_tracee(struct parasite_ctl *ctl, struct swapfd_exchange *se);
int set_parasite_ctl(pid_t pid, struct parasite_ctl **ret_ctl);
void destroy_parasite_ctl(pid_t pid, struct parasite_ctl *ctl);

int swap_fds(struct parasite_ctl *ctl,
	     int *src_fd, int *dst_fd, unsigned long *cloexec, int nfd);
int swap_exe(struct parasite_ctl *ctl, int exe_fd);
int swap_root(struct parasite_ctl *ctl, int cwd_fd, const char *root,
	      bool restore_cwd);
int swap_cwd(struct parasite_ctl *ctl, int cwd_fd);


int swap_map(struct parasite_ctl *ctl, int map_fd,
	     unsigned long start, unsigned long end,
	     int prot, int flags, unsigned long long pgoff);

#endif
