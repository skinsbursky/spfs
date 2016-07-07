#ifndef __SPFS_MANAGER_FILE_OBJ_H_
#define __SPFS_MANAGER_FILE_OBJ_H_

int create_fd_obj(const char *path, unsigned flags, mode_t mode,
		  int source_fd, void *file_obj);
int get_file_obj_fd(void *file_obj, unsigned flags);
void destroy_fd_obj(void *file_obj);

#endif
