#ifndef __SPFS_UTIL_H_
#define __SPFS_UTIL_H_

extern char *xstrcat(char *str, const char *fmt, ...);
extern char *xsprintf(const char *fmt, ...);

int save_fd(int fd);

void execvp_print(const char *file, char *const argv[]);

#endif
