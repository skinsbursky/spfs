#ifndef __SPFS_UTIL_H_
#define __SPFS_UTIL_H_

extern char *xstrcat(char *str, const char *fmt, ...);
extern char *xsprintf(const char *fmt, ...);

extern int xatol(const char *string, long *number);

int save_fd(int fd);

void execvp_print(const char *file, char *const argv[]);

int create_dir(const char *fmt, ...);

int close_inherited_fds(void);

#endif
