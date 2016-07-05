#ifndef __SPFS_MANAGER_TREES_H_
#define __SPFS_MANAGER_TREES_H_

struct replace_fd {
	pid_t pid;
	int fd;
	void *file_obj;
	bool shared;
};

int collect_fd(pid_t pid, int fd, void *file_obj, struct replace_fd **rfd);
pid_t fd_table_exists(pid_t pid);
int collect_fd_table(pid_t pid);
int collect_fs_struct(pid_t pid);
int collect_map_fd(int fd, const char *path, mode_t mode, int *map_fd);
int collect_fifo(const char *path);
pid_t mm_exists(pid_t pid);
int collect_mm(pid_t pid);

void destroy_obj_trees(void);

#endif
