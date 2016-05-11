#ifndef __SPFS_MANAGER_FD_TREE_H_
#define __SPFS_MANAGER_FD_TREE_H_

struct replace_fd {
	pid_t pid;
	mode_t mode;
	int spfs_fd;
	void *file_obj;
	bool shared;
};

int add_fd_to_tree(pid_t pid, int fd, struct replace_fd **rfd);

#endif
