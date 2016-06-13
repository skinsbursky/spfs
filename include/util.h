#ifndef __SPFS_UTIL_H_
#define __SPFS_UTIL_H_

#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>

char *xvstrcat(char *str, const char *fmt, va_list args);
extern char *xstrcat(char *str, const char *fmt, ...);
extern char *xsprintf(const char *fmt, ...);

int xatol_base(const char *string, long *number, int base);
extern int xatol(const char *string, long *number);

int save_fd(int fd, unsigned flags);

int execvp_print(const char *file, char *const argv[]);

int create_dir(const char *fmt, ...);

int close_inherited_fds(void);

int collect_child(int pid, int *status, int options);

int check_capabilities(unsigned long cap_set, pid_t pid);

int secure_chroot(const char *root);

char **exec_options(int dummy, ...);
char **add_exec_options(char **options, ...);

bool unlinked_path(const char *path);

void strip_deleted(char *path);

#endif
