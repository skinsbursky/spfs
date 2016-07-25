#ifndef __SPFS_MANAGER_UNIX_SOCKETS_H_
#define __SPFS_MANAGER_UNIX_SOCKETS_H_

struct replace_info_s;
int collect_unix_sockets(struct replace_info_s *ri);

int unix_sk_file_open(const char *cwd, unsigned flags, int source_fd);
bool unix_sk_early_open(const char *cwd, unsigned flags, int source_fd);

#endif
