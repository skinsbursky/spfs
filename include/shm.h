#ifndef __SPFS_SHM_H_
#define __SPFS_SHM_H_

int shm_init_pool(void);
void *shm_alloc(size_t size);

#endif
