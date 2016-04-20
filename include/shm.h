#ifndef __SPFS_SHM_H_
#define __SPFS_SHM_H_

#include <semaphore.h>

#include "include/list.h"

struct shared_list {
	struct list_head	list;
	sem_t			sem;
};

int init_shared_list(struct shared_list *sl);
struct shared_list *create_shared_list(void);
int lock_shared_list(struct shared_list *sl);
int unlock_shared_list(struct shared_list *sl);

int shm_init_pool(void);
void *shm_alloc(size_t size);

#endif
