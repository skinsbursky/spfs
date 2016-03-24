#ifndef __SPFS_LOG_H_
#define __SPFS_LOG_H_

#include <stdio.h>
#include <sys/syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <syscall.h>
#include <string.h>

static inline pid_t gettid(void)
{
	return syscall(SYS_gettid);
}

extern const char *__progname;

int print_on_level_va(unsigned int level, const char *format, va_list args);
int print_on_level(unsigned int level, const char *format, ...);

#define print_with_header(verbosity, fmt, ...)			\
({								\
	char *v = #verbosity;					\
								\
	print_on_level(LOG_ ## verbosity,			\
			"%s(%d): %s%*s: "fmt,			\
			__progname, gettid(), v,		\
			7 - strlen(v), "",			\
			##__VA_ARGS__);				\
})

#define pr_emerg(fmt, ...)					\
	print_with_header(EMERG, fmt, ##__VA_ARGS__)

#define pr_alert(fmt, ...)					\
	print_with_header(ALERT, fmt, ##__VA_ARGS__)

#define pr_crit(fmt, ...)					\
	print_with_header(CRIT, fmt, ##__VA_ARGS__)

#define pr_err(fmt, ...)					\
	print_with_header(ERR, fmt, ##__VA_ARGS__)

#define pr_warn(fmt, ...)					\
	print_with_header(WARNING, fmt, ##__VA_ARGS__)

#define pr_notice(fmt, ...)					\
	print_with_header(NOTICE, fmt, ##__VA_ARGS__)

#define pr_info(fmt, ...)					\
	print_with_header(INFO, fmt, ##__VA_ARGS__)

#define pr_debug(fmt, ...)					\
	print_with_header(DEBUG, fmt, ##__VA_ARGS__)

#define pr_perror(fmt, ...)					\
({								\
	int _errno = errno;					\
	print_with_header(ERR, fmt": %s\n", ##__VA_ARGS__,	\
					strerror(errno));	\
	errno = _errno;						\
})

void set_log_level(FILE *log, int level);
int setup_log(const char *log_file, int verbosity);

#endif
