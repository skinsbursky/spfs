#ifndef __SPFS_MANAGER_TREES_H_
#define __SPFS_MANAGER_TREES_H_

int collect_fd(pid_t pid, int fd, void *file_obj, void **real_file_obj);
pid_t fd_table_exists(pid_t pid);
int collect_fd_table(pid_t pid);
pid_t fs_struct_exists(pid_t pid);
int collect_fs_struct(pid_t pid);
int collect_open_path(const char *path, unsigned flags, void *file_obj, void **real_file_obj);
int collect_fifo(const char *path);
pid_t mm_exists(pid_t pid);
int collect_mm(pid_t pid);

void destroy_obj_trees(void);

#endif
