#ifndef __SPFS_MANAGER_SWAP_H
#define __SPFS_MANAGER_SWAP_H

struct list_head;

int do_swap_resources(const struct list_head *processes);

#endif
