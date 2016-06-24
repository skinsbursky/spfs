#include <stdlib.h>
#include <stdbool.h>
#include <sys/mount.h>

#include "include/log.h"
#include "include/shm.h"

#include "mount.h"

static struct mount_info_s *__iterate_mounts(struct list_head *mounts, const void *data,
						bool (*actor)(const struct mount_info_s *info, const void *data))
{
	struct mount_info_s *mnt;

	list_for_each_entry(mnt, mounts, list) {
		if (actor(mnt, data))
			return mnt;
	}

	return NULL;
}

struct mount_info_s *iterate_mounts(struct shared_list *mounts, const void *data,
				    bool (*actor)(const struct mount_info_s *info, const void *data))
{
	struct mount_info_s *mnt = NULL;

	if (lock_shared_list(mounts))
		return NULL;

	mnt = __iterate_mounts(&mounts->list, data, actor);

	(void) unlock_shared_list(mounts);

	return mnt;

}

static bool mnt_id_match(const struct mount_info_s *mnt, const void *data)
{
	const char *id = data;
	return !strcmp(mnt->id, id);
}

struct mount_info_s *find_mount_by_id(struct shared_list *mounts, const char *id)
{
	return iterate_mounts(mounts, id, mnt_id_match);
}

int add_mount_info(struct shared_list *mounts, struct mount_info_s *info)
{
	int err = 0;
	struct list_head *list = &mounts->list;

	if (lock_shared_list(mounts))
		return -EINVAL;

	if (__iterate_mounts(list, info->id, mnt_id_match)) {
		pr_err("mount info with id %s already exists\n", info->id);
		err = -EEXIST;
	} else {
		pr_info("added info with id %s\n", info->id);
		list_add_tail(&info->list, list);
	}

	(void) unlock_shared_list(mounts);

	return err;
}

void del_mount_info(struct shared_list *mounts, struct mount_info_s *info)
{
	if (!lock_shared_list(mounts)) {
		list_del(&info->list);
		(void) unlock_shared_list(mounts);
	}
}

int init_mount_info(struct mount_info_s *mnt, const char *id,
		    const char *mountpoint)
{
	mnt->mountpoint = shm_xsprintf(mountpoint);
	mnt->id = shm_xsprintf(id);
	if (!mnt->mountpoint || !mnt->id) {
		pr_err("failed to allocate shared memory\n");
		return -ENOMEM;
	}
	return 0;
}

static int do_mount(const char *source, const char *mnt,
		    const char *fstype, unsigned long mountflags,
		    const void *options)
{
	int err;

	err = mount(source, mnt, fstype, mountflags, options);
	if (!err)
		return 0;

	switch (errno) {
		case EPROTONOSUPPORT:
		case EPERM:
			pr_warn("failed to mount %s to %s: %s\n", fstype, mnt,
					strerror(errno));
			return -EAGAIN;
	}
	return -errno;
}

int mount_loop(const char *source, const char *mnt, const char *fstype,
	       unsigned long mountflags, const void *options)
{
	int err;
	int timeout = 1;

	pr_debug("trying to mount %s, source %s, flags %ld, options '%s' to %s\n",
			fstype, source, mountflags, options, mnt);

	while (1) {
		err = do_mount(source, mnt, fstype, mountflags, options);
		if (err != -EAGAIN)
			break;

		pr_warn("retrying in %d seconds\n", timeout);
		sleep(timeout);

		if (timeout < 32)
			timeout <<= 1;
	}

	if (err)
		pr_perror("failed to mount %s to %s", fstype, mnt);
	else
		pr_info("Successfully mounted %s to %s\n", fstype, mnt);
	return err;
}
