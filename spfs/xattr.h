#ifndef __SPFS_XATTR_H_
#define __SPFS_XATTR_H_

#include <stdbool.h>

#define SPFS_XATTR_LINK_REMAP		"security.spfs.link_remap"

bool is_spfs_xattr(const char *xattr);
int spfs_del_xattrs(const char *path);

int spfs_setxattr(const char *path, const char *name, const void *value,
		  size_t size, int flags);
int spfs_removexattr(const char *path, const char *name);
ssize_t spfs_getxattr(const char *path, const char *name,
		      void *value, size_t size);
ssize_t spfs_listxattr(const char *path, char *list, size_t size);

int spfs_move_xattrs(const char *from, const char *to);
int spfs_dup_xattrs(const char *from, const char *to);

#endif
