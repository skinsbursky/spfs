#include <stdio.h>
#include <stdarg.h>

#include "include/log.h"

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

void init_log(FILE *log, int level)
{
	stream = log;
	log_level = LOG_ERR + level;
	if (log_level > LOG_DEBUG)
		log_level = LOG_DEBUG;
	pr_info("Log level set to %d\n", log_level);
}
