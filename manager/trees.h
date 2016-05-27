#ifndef __SPFS_MANAGER_TREES_H_
#define __SPFS_MANAGER_TREES_H_

struct replace_fd {
	pid_t pid;
	mode_t mode;
	int fd;
	void *file_obj;
	bool shared;
};

int collect_fd(pid_t pid, int fd, struct replace_fd **rfd);
int collect_fd_table(pid_t pid, bool *exists);
int collect_fs_struct(pid_t pid, bool *exists);

#endif