#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>

#include "include/list.h"
#include "include/log.h"
#include "include/util.h"
#include "include/shm.h"
#include "include/namespaces.h"

#include "spfs.h"
#include "trees.h"
#include "swapfd.h"
#include "processes.h"

typedef enum {
	FTYPE_REG,
	FTYPE_DIR,
	FTYPE_FIFO,
	FTYPE_SOCK,
	FTYPE_LINK,
	FTYPE_CHR,
	FTYPE_BLK,
	FTYPE_MAX,
} file_type_t;

char *file_types[FTYPE_MAX] = {
	"regular",
	"directory",
	"fifo",
	"sock",
	"link",
	"character device",
	"block device",
};

typedef struct fobj_ops_s {
	int (*open)(const char *path, unsigned flags, const char *parent);
} fobj_ops_t;

static int fifo_file_fill(const char *source, unsigned fd)
{
	char path[PATH_MAX];
	int fifo;
	int source_fd, err = 0;
	ssize_t bytes;

	snprintf(path, PATH_MAX, "/proc/%d/fd/%d", getpid(), fd);

	fifo = open(path, O_RDWR);
	if (fifo < 0) {
		pr_perror("failed to open fifo %s in read/write mode", path);
		return -errno;
	}

	source_fd = open(source, O_RDONLY | O_NONBLOCK);
	if (source_fd < 0) {
		pr_perror("failed to open source fifo %s", source);
		err = -errno;
		goto close_fifo_rw;
	}

	bytes = fcntl(source_fd, F_GETPIPE_SZ);
	if (bytes < 0) {
		pr_perror("failed to discover %s capacity", source);
		err = -errno;
		goto close_source_fd;
	}

	bytes = tee(source_fd, fifo, bytes, SPLICE_F_NONBLOCK);
	if ((bytes < 0) && (errno != EAGAIN)) {
		pr_perror("failed to tee data from %s to %s", source, path);
		err = -errno;
		goto close_source_fd;
	}

close_source_fd:
	close(source_fd);
close_fifo_rw:
	close(fifo);
	return err;
}

static int open_fifo_fd(const char *path, unsigned flags)
{
	int fifo_rw, fd;
	int err = 0;

	fifo_rw = open(path, O_RDWR);
	if (fifo_rw < 0) {
		pr_perror("failed to open fifo %s in read/write mode", path);
		return -errno;
	}

	switch (flags & O_ACCMODE) {
		case O_RDWR:
			return fifo_rw;
		case O_RDONLY:
		case O_WRONLY:
			break;
		default:
			pr_err("unknown access mode: 0%o\n", flags & O_ACCMODE);
			err = -EINVAL;
			goto close_fifo_rw;
	}

	fd = open(path, flags);
	if (fd < 0) {
		pr_perror("failed to open fifo %s with 0%o flags", path, flags);
		err = -errno;
	}

close_fifo_rw:
	close(fifo_rw);
	return err ? err : fd;
}

static int fifo_file_open(const char *path, unsigned flags, const char *parent)
{
	int fd, err;

	fd = open_fifo_fd(path, flags);
	if (fd < 0)
		return fd;

	err = collect_fifo(path);
	switch (err) {
		case -EEXIST:
			err = 0;
			break;
		case 0:
			err = fifo_file_fill(parent, fd);
			break;
		default:
			close(fd);
	}

	return err ? err : fd;
}

typedef struct file_obj_s {
	int		fd;
	fobj_ops_t	*ops;
} file_obj_t;

static int reg_file_open(const char *path, unsigned flags, const char *parent)
{
	int fd;

	fd = open(path, flags);
	if (fd < 0) {
		pr_perror("failed to open regular file %s", path);
		return -errno;
	}

	return fd;
}

fobj_ops_t fobj_ops[] = {
	[FTYPE_REG] = {
		.open = reg_file_open,
	},
	[FTYPE_DIR] = {
		.open = reg_file_open,
	},
	[FTYPE_FIFO] = {
		.open = fifo_file_open,
	},
};

static file_type_t convert_mode_to_type(mode_t mode)
{
	switch (mode & S_IFMT) {
		case S_IFREG:
			return FTYPE_REG;
		case S_IFDIR:
			return FTYPE_DIR;
		case S_IFIFO:
			return FTYPE_FIFO;
		case S_IFSOCK:
			return FTYPE_SOCK;
		case S_IFLNK:
			return FTYPE_LINK;
		case S_IFBLK:
			return FTYPE_BLK;
		case S_IFCHR:
			return FTYPE_CHR;
	}
	pr_err("unknown file mode: 0%o\n", mode & S_IFMT);
	return -EINVAL;
}

static int get_file_ops(mode_t mode, fobj_ops_t **ops)
{
	file_type_t type;

	type = convert_mode_to_type(mode);

	switch (type) {
		case FTYPE_REG:
		case FTYPE_DIR:
		case FTYPE_FIFO:
			*ops = &fobj_ops[type];
			return 0;
		case FTYPE_SOCK:
		case FTYPE_LINK:
		case FTYPE_CHR:
		case FTYPE_BLK:
			break;
		default:
			return -EINVAL;
	}

	pr_err("%s is not supported yet\n", file_types[type]);
	return -ENOTSUP;
}

int create_fd_obj(const char *path, unsigned flags, mode_t mode,
		    const char *parent, void **file_obj)
{
	file_obj_t *fobj;
	fobj_ops_t *ops = NULL;
	int err, fd;

	err = get_file_ops(mode, &ops);
	if (err)
		return err;

	fobj = malloc(sizeof(*fobj));
	if (!fobj) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	fd = ops->open(path, flags, parent);
	if (fd < 0) {
		err = fd;
		goto free_fobj;
	}

	fobj->fd = fd;
	fobj->ops = ops;

	*file_obj = fobj;
	return 0;

free_fobj:
	free(fobj);
	return err;
}


int get_file_obj_fd(void *file_obj, unsigned flags)
{
	file_obj_t *fobj = file_obj;

	return fobj->fd;
}
