#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "include/log.h"
#include "include/util.h"

static int log_level = LOG_DEBUG;
FILE *stream;

int print_on_level_va(unsigned int level, const char *format, va_list args)
{
	int saved_errno = errno, res;
	FILE *out = (stream) ? stream : stdout;

	if (level > log_level)
		return 0;

	res = vfprintf(out, format, args);

	errno -= saved_errno;
	return res;
}

int print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list params;
	int res;

	va_start(params, format);
	res = print_on_level_va(loglevel, format, params);
	va_end(params);
	return res;
}

void set_log_level(FILE *log, int level)
{
	log_level = LOG_ERR + level;
	if (log_level > LOG_DEBUG)
		log_level = LOG_DEBUG;
	pr_info("Log level set to %d\n", log_level);
}

int setup_log(const char *log_file, int verbosity)
{
	int fd;
	FILE *log;

	fd = open(log_file, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0644);
	if (fd < 0) {
		pr_perror("%s: failed to open log file", __func__);
		return -errno;
	}
	fd = save_fd(fd);
	if (fd < 0) {
		pr_crit("Failed to save log fd\n");
		return fd;
	}
	pr_debug("Log fd: %d\n", fd);
	log = fdopen(fd, "w+");
	if (!log) {
		pr_perror("failed to open log stream");
		close(fd);
		return -errno;
	}
	setvbuf(log, NULL, _IONBF, 0);
	set_log_level(log, verbosity);
	stream = log;
	return 0;
}


