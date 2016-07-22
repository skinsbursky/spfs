#ifndef __SPFS_MANAGER_FILE_OBJ_H_
#define __SPFS_MANAGER_FILE_OBJ_H_

struct replace_info_s;
int get_file_obj(const char *path, unsigned flags, mode_t mode, int source_fd,
		 const struct replace_info_s *ri,
		 void *cb_data, int (*cb)(void *cb_data, void *new_fobj, void **res_fobj),
		 void **file_obj);
int get_fobj_fd(void *file_obj);
/* This helper should be used only to release memory (usually on
 * error/cleanup paths). */
void put_file_obj(void *file_obj);
/* This helper should be used also to put link remap reference (upon
 * successfull fd replacement). */
void release_file_obj(void *file_obj);

#endif
