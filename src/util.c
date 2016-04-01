#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "include/log.h"

/*
 * This function reallocates passed str pointer.
 * It means:
 *  1) passed pointer can be either NULL, or previously allocated by malloc.
 *  2) Passed pointer can' be reused. It's either freed in case of error or can
 *     be changed.
 */
static char *xvstrcat(char *str, const char *fmt, va_list args)
{
	size_t offset = 0, delta;
	int ret;
	char *new;
	va_list tmp;

	if (str)
		offset = strlen(str);
	delta = strlen(fmt) * 2;

	do {
		ret = -ENOMEM;
		new = realloc(str, offset + delta);
		if (new) {
			va_copy(tmp, args);
			ret = vsnprintf(new + offset, delta, fmt, tmp);
			if (ret >= delta) {
				/* NOTE: vsnprintf returns the amount of bytes
				 *                                  * to allocate. */
				delta = ret +1;
				str = new;
				ret = 0;
			}
		}
	} while (ret == 0);

	if (ret == -ENOMEM) {
		/* realloc failed. We must release former string */
		free(str);
	} else if (ret < 0) {
		/* vsnprintf failed */
		free(new);
		new = NULL;
	}
	return new;
}

char *xstrcat(char *str, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	str = xvstrcat(str, fmt, args);
	va_end(args);

	return str;
}

char *xsprintf(const char *fmt, ...)
{
	va_list args;
	char *str;

	va_start(args, fmt);
	str = xvstrcat(NULL, fmt, args);
	va_end(args);

	return str;
}

int save_fd(int fd)
{
	if (fd <= STDERR_FILENO) {
		int new_fd;

		pr_info("Duplicating decriptor %d to region above standart "
			"descriptors\n", fd);
		/* We need to move log fd away from first 3 descriptors,
		 * because they will be closed. */
		new_fd = fcntl(fd, F_DUPFD, STDERR_FILENO + 1);
		close(fd);
		if (new_fd < 0) {
			pr_perror("duplication of fd %d failed", fd);
			return -errno;
		}
		pr_info("Descriptor %d was moved to %d\n", fd, new_fd);
		fd = new_fd;
	}
	return fd;
}

void execvp_print(const char *file, char *const argv[])
{
	const char **tmp = (const char **)argv;

	pr_info("Executing %s with options: ", file);
	while (*tmp) {
		print_on_level(LOG_INFO, "%s ", *tmp);
		tmp++;
	}
	print_on_level(LOG_INFO, "\n");

	execvp(file, argv);

	pr_perror("exec failed");
}

int xatol(const char *string, long *number)
{
	char *endptr;
	long nr;

	errno = 0;
	nr = strtol(string, &endptr, 10);
	if ((errno == ERANGE && (nr == LONG_MAX || nr == LONG_MIN))
			|| (errno != 0 && nr == 0)) {
		perror("failed to convert string");
		return -EINVAL;
	}

	if ((endptr == string) || (*endptr != '\0')) {
		printf("String is not a number: '%s'\n", string);
		return -EINVAL;
	}
	*number = nr;
	return 0;
}

int create_dir(const char *fmt, ...)
{
	int err = -1;
	char *p, *d, *cp = NULL;
	va_list args;

	va_start(args, fmt);
	p = xvstrcat(NULL, fmt, args);
	va_end(args);
	if (!p) {
		pr_err("failed to allocate string\n");
		return -ENOMEM;
	}

	pr_debug("creating directory %s\n", p);

	while ((d = strsep(&p, "/")) != NULL) {
		cp = xstrcat(cp, "%s/", d);
		if (!cp) {
			err = -ENOMEM;
			goto err;
		}

		err = mkdir(cp, 0777);
		if (!err) {
			pr_debug("created dir: '%s'\n", cp);
			continue;
		}
		if (errno != EEXIST) {
			pr_perror("failed to mkdir %s", cp);
			goto err;
		}
	}
	err = 0;
err:
	free(cp);
	free(p);
	return err;
}
