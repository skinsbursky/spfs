#ifndef __SPFS_MANAGER_PROCESSES_H_
#define __SPFS_MANAGER_PROCESSES_H_

#include <stdbool.h>

#include "include/list.h"

struct replace_info_s {
	dev_t			src_dev;
	int			src_mnt_ref;
	const char		*source_mnt;
	const char		*target_mnt;
};

int get_pids_list(const char *tasks_file, char **list);

int collect_processes(const char *pids, struct list_head *collection);

int examine_processes(struct list_head *collection,
		      const struct replace_info_s *ri);

int iterate_pids_list_name(const char *pids_list, void *data,
			   int (*actor)(pid_t pid, void *data),
			   const char *actor_name);

#define __stringify(x...)     #x
#define stringify(x...)       __stringify(x)

#define iterate_pids_list(pids_list, data, actor)		\
	iterate_pids_list_name(pids_list, data, actor, stringify(actor))

int seize_processes(struct list_head *processes);
void release_processes(struct list_head *processes);

struct process_resource {
	bool			replaced;
	void			*fobj;
};

struct fd_info {
	int			source_fd;
	unsigned long		cloexec;
	long long		pos;
};

struct process_fd {
	struct list_head	list;
	struct fd_info		info;
	struct process_resource	res;
};

struct map_info {
	off_t			start;
	off_t			end;
	int			prot;
	int			flags;
	unsigned long long	pgoff;
};

struct process_map {
	struct list_head	list;
	struct map_info		info;
	struct process_resource	res;
};

struct process_fs {
	char			*root;
	struct process_resource	cwd;
};

struct parasite_ctl;

struct process_info {
	struct list_head	list;
	int			pid;
	int			fds_nr;
	int			maps_nr;
	struct process_fs	fs;
	struct process_resource	exe;
	struct list_head	fds;
	struct list_head	maps;
	struct parasite_ctl	*pctl;
	int			orig_st;
};

int fixup_source_path(char *source_path, size_t source_size,
		      const char *source_mnt, const char *target_mnt);

#endif
