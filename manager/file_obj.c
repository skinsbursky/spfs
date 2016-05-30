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

typedef struct file_obj_s {
	int		fd;
	fobj_ops_t	*ops;
} file_obj_t;

static int reg_file_open(const char *path, unsigned flags, const char *parent)
{
	int fd;

	fd = open(path, flags);
	if (fd < 0) {
		pr_perror("failed to open %s", path);
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

static int get_file_ops(const char *path, fobj_ops_t **ops)
{
	struct stat st;
	file_type_t type;

	if (stat(path, &st)) {
		pr_perror("failed to stat %s", path);
		return -errno;
	}

	type = convert_mode_to_type(st.st_mode);

	switch (type) {
		case FTYPE_REG:
		case FTYPE_DIR:
			*ops = &fobj_ops[type];
			return 0;
		case FTYPE_FIFO:
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

int create_file_obj(const char *path, unsigned flags, const char *parent,
		    void **file_obj)
{
	file_obj_t *fobj;
	fobj_ops_t *ops = NULL;
	int err, fd;

	err = get_file_ops(path, &ops);
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
