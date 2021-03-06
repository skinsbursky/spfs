#include <errno.h>
#include "limits.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include "include/log.h"
#include "include/shm.h"
#include "include/util.h"

#include "freeze.h"
#include "processes.h"

static struct freeze_cgroup_s *__find_freeze_cgroup(const struct shared_list *groups, const char *path)
{
	struct freeze_cgroup_s *fg;

	list_for_each_entry(fg, &groups->list, list) {
		if (!strcmp(fg->path, path))
			return fg;
	}

	return NULL;
}

static struct freeze_cgroup_s *create_freeze_cgroup(const char *path)
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

struct freeze_cgroup_s *get_freeze_cgroup(struct shared_list *list, const char *path)
{
	int err;
	struct freeze_cgroup_s *fg;

	err = lock_shared_list(list);
	if (err)
		return NULL;

	fg = __find_freeze_cgroup(list, path);
	if (!fg) {
		fg = create_freeze_cgroup(path);
		if (!fg)
			pr_err("failed to create freezer object\n");
		else
			list_add_tail(&fg->list, &list->list);
	}

	(void) unlock_shared_list(list);
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

static int freezer_open_state(const char *freezer_cgroup)
{
	int fd;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/freezer.state", freezer_cgroup);
	fd = open(path, O_RDWR);
	if (fd < 0) {
		pr_perror("Unable to open %s", path);
		return -1;
	}
	return fd;
}

static int freezer_set_state(const char *freezer_cgroup, const char *state)
{
	int fd, err = 0, tries = 100;

	fd = freezer_open_state(freezer_cgroup);
	if (fd < 0)
		return fd;

	if (write(fd, state, strlen(state)) != strlen(state)) {
		pr_perror("Unable to set %s state to %s", freezer_cgroup, state);
		err = -errno;
		goto close_fd;
	}

	/* We should wait while state is updated in reality */
	while (tries--) {
		char cstate[16];
		ssize_t bytes;

		if (lseek(fd, 0, SEEK_SET)) {
			pr_err("failed to lseek fd %d", fd);
			err = -errno;
			goto close_fd;
		}

		bytes = read(fd, cstate, sizeof(cstate));
		if (bytes < 0) {
			pr_perror("failed to read %s state", freezer_cgroup);
			err = -errno;
			goto close_fd;
		}
		cstate[bytes-1] = '\0';

		if (!strcmp(state, cstate))
			break;

		usleep(100 * 1000);
	}

	if (tries < 0) {
		pr_err("timed out to set state %s to freezer cgroup %s\n",
				state, freezer_cgroup);
		err = -ETIMEDOUT;
	}

close_fd:
	close(fd);
	return err;
}

int thaw_cgroup(const struct freeze_cgroup_s *fg)
{
	int err;

	err = freezer_set_state(fg->path, "THAWED");
	if (err) {
		freezer_set_state(fg->path, "FROZEN");
		pr_err("failed to thaw cgroup %s\n", fg->path);
	} else
		pr_debug("cgroup %s was thawed\n", fg->path);
	return err;
}

int freeze_cgroup(const struct freeze_cgroup_s *fg)
{
	int err;

	err = freezer_set_state(fg->path, "FROZEN");
	if (err) {
		freezer_set_state(fg->path, "THAWED");
		pr_err("failed to freeze cgroup %s\n", fg->path);
	} else
		pr_debug("cgroup %s was frozen\n", fg->path);
	return err;
}

int cgroup_pids(const struct freeze_cgroup_s *fg, char **list)
{
	char *tasks_file;
	int err;

	tasks_file = xsprintf("%s/tasks", fg->path);
	if (!tasks_file)
		return -ENOMEM;

	err = get_pids_list(tasks_file, list);

	free(tasks_file);
	return err;
}
