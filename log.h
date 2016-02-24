#ifndef __LOG_FUSE_FS_H_
#define __LOG_FUSE_FS_H_

#include <sys/syslog.h>
#include <errno.h>

#define pr_emerg(fmt, ...)			\
	print_on_level(LOG_EMERG,		\
			"EMERG : "fmt, ##__VA_ARGS__)

#define pr_alert(fmt, ...)			\
	print_on_level(LOG_ALERT,		\
			"ALERT : "fmt, ##__VA_ARGS__)

#define pr_crit(fmt, ...)			\
	print_on_level(LOG_CRIT,		\
			"CRIT  : "fmt, ##__VA_ARGS__)

#define pr_err(fmt, ...)			\
	print_on_level(LOG_ERR,			\
			"ERR   : "fmt, ##__VA_ARGS__)

#define pr_warn(fmt, ...)			\
	print_on_level(LOG_WARNING,		\
			"WARN  : "fmt, ##__VA_ARGS__)

#define pr_notice(fmt, ...)			\
	print_on_level(LOG_NOTICE,		\
			"NOTICE: "fmt, ##__VA_ARGS__)

#define pr_info(fmt, ...)			\
	print_on_level(LOG_INFO,		\
			"INFO  : "fmt, ##__VA_ARGS__)

#define pr_debug(fmt, ...)			\
	print_on_level(LOG_DEBUG,		\
			"DEBUG : "fmt, ##__VA_ARGS__)

#define pr_perror(fmt, ...)			\
({						\
	int _errno = errno;			\
        print_on_level(LOG_ERR,			\
                       "ERR: "fmt": %d\n",	\
		       ##__VA_ARGS__, errno);	\
	errno = _errno;				\
})

int print_on_level_va(unsigned int level, const char *format, va_list args);
int print_on_level(unsigned int level, const char *format, ...);

void init_log(FILE *log, int level);

#endif
