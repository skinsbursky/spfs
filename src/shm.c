#include <semaphore.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>

#include <sys/user.h>
#include <sys/mman.h>

#include "include/log.h"
#include "include/shm.h"
#include "include/util.h"

#define __round_mask(x, y)      ((__typeof__(x))((y) - 1))
#define round_up(x, y)          ((((x) - 1) | __round_mask(x, y)) + 1)

#define shm_align(x)		(round_up(x, sizeof(long)))

static struct shared_memory_pool {
	void	*data;
	size_t	alloc_size;
	size_t	used_size;
	sem_t	sem;
} *pool;

#define shm_fit(x)		(pool->used_size + x <= pool->alloc_size)

int shm_init_pool(void)
{
	size_t size = PAGE_SIZE << 4;

	pool = mmap(NULL, size, PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (pool == MAP_FAILED) {
		pr_perror("failed to allocate shared memory pool");
		return -errno;
	}

	if (sem_init(&pool->sem, 1, 1)) {
		pr_perror("failed to init shared memory semaphore");
		munmap(pool, size);
		return -errno;
	}

	pool->data = pool + sizeof(*pool);
	pool->alloc_size = size;
	pool->used_size = shm_align(sizeof(*pool));

	return 0;
}

static int shm_grow_pool(size_t size)
{
	size_t grow_size;

	grow_size = round_up(size, PAGE_SIZE);

	if (mremap(pool, pool->alloc_size, pool->alloc_size + grow_size, 0) == MAP_FAILED) {
		pr_perror("failed to grow shared memory pool");
		return -errno;
	}

	pool->alloc_size += grow_size;
	return 0;
}

void *shm_alloc(size_t size)
{
	size_t alloc_size;
	void *ptr = NULL;

	alloc_size = round_up(size, sizeof(long));

	if (sem_wait(&pool->sem)) {
		pr_perror("failed to lock shared memory semaphore");
		return NULL;
	}

	if (!shm_fit(alloc_size)) {
		if (shm_grow_pool(alloc_size))
			goto unlock;
	}

	ptr = pool->data + pool->used_size;
	pool->used_size += alloc_size;

	pr_debug("%s: allocated %ld, return 0x%lx\n", __func__, alloc_size, ptr);
unlock:
	if (sem_post(&pool->sem))
		pr_perror("failed to unlock spfs semaphore");

	return ptr;
}

void *shm_xsprintf(const char *fmt, ...)
{
	void *ptr;
	char *string;
	va_list args;

	va_start(args, fmt);
	string = xvstrcat(NULL, fmt, args);
	va_end(args);
	if (!string) {
		pr_err("failed to allocate string\n");
		return NULL;
	}

	ptr = shm_alloc(strlen(string) + 1);
	if (ptr)
		strcpy(ptr, string);
	else
		pr_err("failed to allocate shated string\n");
	free(string);
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
