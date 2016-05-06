#include "errno.h"
#include "limits.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "include/log.h"
#include "include/shm.h"

#include "freeze.h"

struct freeze_cgroup_s *__find_freeze_cgroup(const struct shared_list *groups, const char *path)
{
	struct freeze_cgroup_s *fg;

	list_for_each_entry(fg, &groups->list, list) {
		if (!strcmp(fg->path, path))
			return fg;
	}

	return NULL;
}

struct freeze_cgroup_s *create_freeze_cgroup(const char *path)
{
	struct freeze_cgroup_s *fg;

	fg = shm_alloc(sizeof(*fg));
	if (!fg) {
		pr_err("failed to allocate freeze cgroup\n");
		return NULL;
	}

	fg->path = shm_xsprintf(path);
	if (!fg->path) {
		pr_err("failed to allocate string\n");
		return NULL;
	}

	if (sem_init(&fg->sem, 1, 1)) {
		pr_perror("failed to initialize freeze cgroup semaphore");
		return NULL;
	}

	return fg;
}

int lock_cgroup(struct freeze_cgroup_s *fg)
{
	if (sem_wait(&fg->sem)) {
		pr_perror("failed to lock cgroup %s", fg->path);
		return -errno;
	}
	pr_debug("cgroup %s was locked\n", fg->path);
	return 0;
}

int unlock_cgroup(struct freeze_cgroup_s *fg)
{
	if (sem_post(&fg->sem)) {
		pr_perror("failed to unlock cgroup %s", fg->path);
		return -errno;
	}
	pr_debug("cgroup %s was unlocked\n", fg->path);
	return 0;
}

static int freezer_set_state(const char *freezer_cgroup, const char state[])
{
	int fd;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/freezer.state", freezer_cgroup);
	fd = open(path, O_RDWR);
	if (fd < 0) {
		pr_perror("Unable to open %s", path);
		return -1;
	}

	if (write(fd, state, sizeof(state)) != sizeof(state)) {
		pr_perror("Unable to set %s state to %s", freezer_cgroup, state);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int thaw_cgroup(const struct freeze_cgroup_s *fg)
{
	int err;

	err = freezer_set_state(fg->path, "THAWED");
	if (err)
		pr_err("failed to thaw cgroup %s\n", fg->path);
	else
		pr_debug("cgroup %s was thawed\n", fg->path);
	return err;
}

static int freeze_cgroup(const struct freeze_cgroup_s *fg)
{
	int err;

	err = freezer_set_state(fg->path, "FROZEN");
	if (err)
		pr_err("failed to freeze cgroup %s\n", fg->path);
	else
		pr_debug("cgroup %s was frozen\n", fg->path);
	return err;
}

int thaw_cgroup_and_unlock(struct freeze_cgroup_s *fg)
{
	int err;

	if (!fg)
		return 0;

	err = thaw_cgroup(fg);
	if (!err)
		(void) unlock_cgroup(fg);

	return err;
}

int lock_cgroup_and_freeze(struct freeze_cgroup_s *fg)
{
	int err;

	if (!fg)
		return 0;

	err = lock_cgroup(fg);
	if (err)
		return err;

	err = freeze_cgroup(fg);
	if (err)
		(void) unlock_cgroup(fg);

	return err;
}
