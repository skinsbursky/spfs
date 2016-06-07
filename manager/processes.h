#ifndef __SPFS_MANAGER_PROCESSES_H_
#define __SPFS_MANAGER_PROCESSES_H_

#include "include/list.h"

struct mount_info_s;

int get_pids_list(const char *tasks_file, char **list);

int collect_processes(const char *pids, struct list_head *collection);

int examine_processes_by_dev(struct list_head *collection,
			     dev_t src_dev, const char *target_mnt);

int examine_processes_by_mnt(struct list_head *collection,
			     const char *source_mnt, const char *target_mnt);

int iterate_pids_list_name(const char *pids_list, void *data,
			   int (*actor)(pid_t pid, void *data),
			   const char *actor_name);

#define __stringify(x...)     #x
#define stringify(x...)       __stringify(x)

#define iterate_pids_list(pids_list, data, actor)		\
	iterate_pids_list_name(pids_list, data, actor, stringify(actor))

int seize_processes(struct list_head *processes);
int release_processes(struct list_head *processes);

struct replace_fd;

struct process_fd {
	struct list_head list;
	int source_fd;
	int target_fd;
};

struct process_map {
	struct list_head list;
	int map_fd;
	off_t start;
	off_t end;
};

struct parasite_ctl;

struct process_info {
	struct list_head list;
	int pid;
	int fds_nr;
	int maps_nr;
	int exe_fd;
	struct process_fs {
		int cwd_fd;
		char *root;
	} fs;
	struct list_head fds;
	struct list_head maps;
	struct parasite_ctl *pctl;
};

#endif
