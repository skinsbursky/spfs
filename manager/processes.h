#ifndef __SPFS_MANAGER_PROCESSES_H_
#define __SPFS_MANAGER_PROCESSES_H_

#include "include/list.h"

struct mount_info_s;

int get_pids_list(const char *tasks_file, char **list);

int collect_dev_processes(const char *pids, struct list_head *collection,
			  dev_t src_dev, const char *target_mnt);
int collect_mnt_processes(const char *pids, struct list_head *collection,
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

enum {
	NS_UTS,
	NS_MNT,
	NS_NET,
	NS_PID,
	NS_USER,
	NS_MAX
};

#define NS_UTS_MASK	(1 << NS_UTS)
#define NS_MNT_MASK	(1 << NS_MNT)
#define NS_NET_MASK	(1 << NS_NET)
#define NS_PID_MASK	(1 << NS_PID)
#define NS_USER_MASK	(1 << NS_USER)

#define NS_ALL_MASK	NS_UTS_MASK | NS_MNT_MASK | NS_NET_MASK |	\
			NS_PID_MASK | NS_USER_MASK

int open_ns(pid_t pid, const char *ns);
int set_namespaces(int *ns_fds, unsigned ns_mask);
int change_namespaces(pid_t pid, unsigned ns_mask, int *orig_ns_fds[]);
int close_namespaces(int *ns_fds);
int open_namespaces(pid_t pid, int *ns_fds);

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

struct process_info {
	struct list_head list;
	int pid;
	int fds_nr;
	int maps_nr;
	union {
		struct process_env {
			int exe_fd;
			int cwd_fd;
			int root_fd;
		} env;
		int env_array[3];
	};
	struct list_head fds;
	struct list_head maps;
};

#endif
