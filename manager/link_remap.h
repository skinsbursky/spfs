#ifndef __SPFS_MANAGER_LINK_REMAP_H_
#define __SPFS_MANAGER_LINK_REMAP_H_

struct link_remap_s;
void put_link_remap(struct link_remap_s *link_remap);
void destroy_link_remap_tree(void);

struct replace_info_s;
int handle_sillyrenamed(const char *path, const struct replace_info_s *ri,
			struct link_remap_s **link_remap);

#endif
