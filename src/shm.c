#include <semaphore.h>
#include <errno.h>

#include <sys/user.h>
#include <sys/mman.h>

#include "include/log.h"
#include "include/shm.h"

#define __round_mask(x, y)      ((__typeof__(x))((y) - 1))
#define round_up(x, y)          ((((x) - 1) | __round_mask(x, y)) + 1)

#define shm_align(x)		(round_up(x, sizeof(long)))
#define shm_fit(x)		(shm_used_size + x <= shm_alloc_size)

void *shm_pool;
size_t shm_alloc_size;
size_t shm_used_size;
sem_t *shm_pool_sem;

int shm_init_pool(void)
{
	size_t size = PAGE_SIZE << 4;

	shm_pool = mmap(NULL, size, PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shm_pool == MAP_FAILED) {
		pr_perror("failed to allocate shared memory pool");
		return -errno;
	}
	shm_alloc_size = size;

	shm_pool_sem = shm_pool;
	if (sem_init(shm_pool_sem, 1, 1)) {
		pr_perror("failed to init shared memory semaphore");
		munmap(shm_pool, size);
		return -errno;
	}

	shm_used_size += shm_align(sizeof(*shm_pool_sem));

	return 0;
}

static int shm_grow_pool(size_t size)
{
	size_t grow_size;

	grow_size = round_up(size, PAGE_SIZE);

	if (mremap(shm_pool, shm_alloc_size, shm_alloc_size + grow_size, 0) == MAP_FAILED) {
		pr_perror("failed to grow shared memory pool");
		return -errno;
	}

	shm_alloc_size += grow_size;
	return 0;
}

void *shm_alloc(size_t size)
{
	size_t alloc_size;
	void *ptr = NULL;

	alloc_size = round_up(size, sizeof(long));

	if (sem_wait(shm_pool_sem)) {
		pr_perror("failed to lock shared memory semaphore");
		return NULL;
	}

	if (!shm_fit(alloc_size)) {
		if (shm_grow_pool(alloc_size))
			goto unlock;
	}

	ptr = shm_pool + shm_used_size;
	shm_used_size += alloc_size;

unlock:
	if (sem_post(shm_pool_sem))
		pr_perror("failed to unlock spfs semaphore");

	return ptr;
}

int init_shared_list(struct shared_list *sl)
{
	if (sem_init(&sl->sem, 1, 1)) {
		pr_perror("failed to initialize spfs info semaphore");
		return -errno;
	}

	INIT_LIST_HEAD(&sl->list);
	return 0;
}

struct shared_list *create_shared_list(void)
{
	struct shared_list *sl;

	sl = shm_alloc(sizeof(*sl));
	if (!sl) {
		pr_err("failed to allocate shared list\n");
		return NULL;
	}

	if (init_shared_list(sl))
		return NULL;

	return sl;
}

int lock_shared_list(struct shared_list *sl)
{
	if (sem_wait(&sl->sem)) {
		pr_perror("failed to lock shared list semaphore");
		return -errno;
	}
	return 0;
}

int unlock_shared_list(struct shared_list *sl)
{
	if (sem_post(&sl->sem)) {
		pr_perror("failed to unlock shared list semaphore");
		return -errno;
	}
	return 0;
}
