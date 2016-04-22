#ifndef __SPFS_MANAGER_SPFS_H_
#define __SPFS_MANAGER_SPFS_H_

#include <unistd.h>
#include <stdbool.h>
#include <semaphore.h>

#include <sys/stat.h>

#include "include/list.h"
#include "include/shm.h"

#include "spfs/context.h"
#include "spfs/interface.h"

struct freeze_cgroup_s;

struct spfs_bindmount {
	struct list_head	list;
	char			*path;
};

struct spfs_info_s {
	struct list_head	list;
	char			*id;
	long			ns_pid;
	char			*ns_list;
	char			*root;
	char			*mountpoint;
	int			ref_cnt;
	char			*work_dir;
	char			*socket_path;
	int			sock;
	pid_t			pid;
	struct stat		root_stat;
	struct freeze_cgroup_s	*fg;
	bool			dead;
	struct shared_list	mountpaths;
};

struct spfs_info_s *find_spfs_by_id(struct shared_list *mounts, const char *id);
struct spfs_info_s *__find_spfs_by_pid(struct shared_list *mounts, pid_t pid);
struct spfs_info_s *find_spfs_by_pid(struct shared_list *mounts, pid_t pid);
int add_spfs_info(struct shared_list *mounts, struct spfs_info_s *info);
void del_spfs_info(struct shared_list *mounts, struct spfs_info_s *info);

int spfs_add_mount_paths(struct spfs_info_s *info, const char *bind_mounts);

int enter_spfs_context(const struct spfs_info_s *info);

int spfs_send_mode(const struct spfs_info_s *info,
		   spfs_mode_t mode, const char *proxy_dir);

int spfs_freeze_ct(struct spfs_info_s *info);
int spfs_thaw_ct(struct spfs_info_s *info);

#endif
