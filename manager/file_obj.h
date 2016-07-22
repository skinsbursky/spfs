#ifndef __SPFS_MANAGER_FILE_OBJ_H_
#define __SPFS_MANAGER_FILE_OBJ_H_

int create_fd_obj(const char *path, unsigned flags, mode_t mode,
		  int source_fd, void **file_obj);
int get_file_obj_fd(void *file_obj, unsigned flags);
void destroy_fd_obj(void *file_obj);

struct link_remap_s;
struct replace_info_s;
int create_file_object(const struct replace_info_s *ri,
		const char *path, unsigned flags, mode_t mode,
		int source_fd, void **file_obj,
		struct link_remap_s **link_remap,
		int (*create_obj)(const char *path, unsigned flags,
			mode_t mode, int source_fd,
			void **file_obj));
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
