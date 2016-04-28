#ifndef __SPFS_MANAGER_SWAPFD_H
#define __SPFS_MANAGER_SWAPFD_H

#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

int swapfd(pid_t pid, bool (*match_fn) (pid_t pid, int fd, char *path, void *data),
	   void (*dst_name_fn) (pid_t pid, char *name, void *data), void *data);
#endif
