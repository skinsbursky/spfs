#ifndef __SPFS_UTIL_H_
#define __SPFS_UTIL_H_

extern char *xstrcat(char *str, const char *fmt, ...);
extern char *xsprintf(const char *fmt, ...);

extern int xatol(const char *string, long *number);

int save_fd(int fd);

void execvp_print(const char *file, char *const argv[]);

int create_dir(const char *fmt, ...);

int close_inherited_fds(void);

int collect_child(int pid, int *status, int options);

int check_capabilities(unsigned long cap_set, pid_t pid);

int secure_chroot(const char *root);

#endif
