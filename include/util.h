#ifndef __UTIL_FUSE_FS_H_
#define __UTIL_FUSE_FS_H_

extern char *xstrcat(char *str, const char *fmt, ...);
extern char *xsprintf(const char *fmt, ...);

int save_fd(int fd);

#endif
