#ifndef __SPFS_MANAGER_LINK_REMAP_H_
#define __SPFS_MANAGER_LINK_REMAP_H_

struct link_remap_s;
int get_link_remap(const char *path, struct link_remap_s **link_remap);
void put_link_remap(struct link_remap_s *link_remap);
void destroy_link_remap_tree(void);

#endif
