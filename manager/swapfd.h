#ifndef __SPFS_MANAGER_SWAPFD_H__
#define __SPFS_MANAGER_SWAPFD_H__

pid_t attach_to_task(pid_t pid);
int detach_from_task(pid_t pid);
int wait_task_seized(pid_t pid);
int swapfd_tracee(pid_t pid, unsigned long addr[], int addr_fd[], int naddr,
		  int src_fd[], int dst_fd[], int nfd);

#endif
