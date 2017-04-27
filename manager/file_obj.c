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
#include "unix-sockets.h"
#include "link_remap.h"
#include "file_obj.h"

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

struct file_obj_s;

typedef struct fobj_ops_s {
	int (*open)(const char *path, unsigned flags, int source_fd);
	bool (*early_open)(const char *path, unsigned flags, int source_fd);
	void (*close)(struct file_obj_s *fobj);
} fobj_ops_t;

static int fifo_file_fill(int source_fd, int destination_fd)
{
	char dest_path[PATH_MAX];
	char src_path[PATH_MAX];
	int fifo_src, fifo_dst, err = 0;
	ssize_t bytes;

	snprintf(src_path, PATH_MAX, "/proc/%d/fd/%d", getpid(), source_fd);
	snprintf(dest_path, PATH_MAX, "/proc/%d/fd/%d", getpid(), destination_fd);

	fifo_src = open(src_path, O_RDONLY | O_NONBLOCK);
	if (fifo_src < 0) {
		pr_perror("failed to open source fifo %s", src_path);
		return -errno;
	}

	fifo_dst = open(dest_path, O_RDWR);
	if (fifo_dst < 0) {
		pr_perror("failed to open destination fifo %s", dest_path);
		err = -errno;
		goto close_fifo_src;
	}

	bytes = fcntl(fifo_src, F_GETPIPE_SZ);
	if (bytes < 0) {
		pr_perror("failed to discover fd %d capacity", fifo_src);
		err = -errno;
		goto close_fifo_dst;
	}

	bytes = tee(fifo_src, fifo_dst, bytes, SPLICE_F_NONBLOCK);
	if ((bytes < 0) && (errno != EAGAIN)) {
		pr_perror("failed to tee data from fd %d to fd %d",
				fifo_src, fifo_dst);
		err = -errno;
	}

close_fifo_dst:
	close(fifo_dst);
close_fifo_src:
	close(fifo_src);
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

static int fifo_file_open(const char *path, unsigned flags, int source_fd)
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
			err = fifo_file_fill(source_fd, fd);
			break;
	}
	if (err)
		close(fd);
	return err ? err : fd;
}

typedef struct file_obj_s {
	char				*path;
	unsigned			flags;
	int				source_fd;
	int				fd;
	const struct replace_info_s	*ri;
	struct link_remap_s		*link_remap;
	fobj_ops_t			*ops;
	unsigned			users;
} file_obj_t;

static int reg_file_open(const char *path, unsigned flags, int source_fd)
{
	int fd;

	fd = open(path, flags);
	if (fd < 0) {
		pr_perror("failed to open regular file %s", path);
		return -errno;
	}

	return fd;
}

static void reg_file_close(struct file_obj_s *fobj)
{
	if (close(fobj->fd))
		pr_perror("failed to close fd %d", fobj->fd);
}

fobj_ops_t fobj_ops[] = {
	[FTYPE_REG] = {
		.open = reg_file_open,
		.close = reg_file_close,
	},
	[FTYPE_DIR] = {
		.open = reg_file_open,
		.close = reg_file_close,
	},
	[FTYPE_FIFO] = {
		.open = fifo_file_open,
		.close = reg_file_close,
	},
	[FTYPE_SOCK] = {
		.open = unix_sk_file_open,
		.early_open = unix_sk_early_open,
		.close = reg_file_close,
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
		case FTYPE_SOCK:
			*ops = &fobj_ops[type];
			return 0;
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

static bool need_to_open_file(file_obj_t *fobj)
{
	/* Silly-renamed files are remapped to some other inode.
	 * And one remmaped inode can be used for multiple opened silly-renamed
	 * files with the same name, but with different open flags, and thus not shared.
	 * Thus this is a shared resource which we need to grab on creation.
	 */

	/* TODO: the restriction above can be removed by more wisely creation
	 * of link_remap object.
	 * Say, link_remap contains not only link path, but also path to link
	 * to.
	 * It is also required to created final path on link remap creation.
	 * It this case handing of link remap can be called on file object
	 * creation, but not opening.
	 * Which allows to postpone opening of remmaped file till is is required.
	 * ZDTM test "static/unlink_mmap01" illustrates the advantage: it has
	 * to fd for the same unlinked path with different flags, so it should
	 * be only one link_remap object for two different file objects.
	 * And linkking link_remap file can be done only once on link_remap
	 * object creation.
	 */
	if (sillyrenamed_path(fobj->path))
		return true;
	if (fobj->ops->early_open)
		return fobj->ops->early_open(fobj->path, fobj->flags, fobj->source_fd);
	return false;
}

static int open_file_obj(file_obj_t *fobj)
{
	int fd, err;
	bool sillyrenamed = sillyrenamed_path(fobj->path);

	if (sillyrenamed) {
		char *renamed_path = NULL;

		err = handle_sillyrenamed(fobj->path, fobj->ri,
					  &fobj->link_remap, &renamed_path);
		if (err)
			return err;

		if (renamed_path) {
			free(fobj->path);
			fobj->path = renamed_path;
		}
	}

	/* TODO it makes sense to create file objects (open files) only
	 * shared files here.
	 * Private files can be opened by the process itself */
	fd = fobj->ops->open(fobj->path, fobj->flags, fobj->source_fd);
	if (fd < 0)
		pr_err("failed to open file object for %s: %d\n", fobj->path, fd);

	if (sillyrenamed) {
		if (unlink(fobj->path)) {
			pr_perror("failed to unlink %s", fobj->path);
			return err;
		}
	}

	return fd;
}

static int create_file_obj(const char *path, unsigned flags,
			   mode_t mode, int source_fd,
			   const struct replace_info_s *ri,
			   file_obj_t **file_obj)
{
	file_obj_t *fobj;
	fobj_ops_t *ops = NULL;
	int err;

	err = get_file_ops(mode, &ops);
	if (err)
		return err;

	fobj = malloc(sizeof(*fobj));
	if (!fobj) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	fobj->path = strdup(path);
	if (!fobj->path) {
		pr_err("failed to duplicate\n");
		err = -ENOMEM;
		goto free_fobj;
	}

	fobj->source_fd = -1;
	if (source_fd >= 0) {
		fobj->source_fd = dup(source_fd);
		if (fobj->source_fd < 0) {
			pr_perror("failed to dup fd %d", source_fd);
			err = -errno;
			goto free_fobj_path;
		}
	}

	fobj->fd = -1;
	fobj->flags = flags;
	fobj->ops = ops;
	fobj->ri = ri;
	fobj->link_remap = NULL;
	fobj->users = 0;

	*file_obj = fobj;
	return 0;

free_fobj_path:
	free(fobj->path);
free_fobj:
	free(fobj);
	return err;
}

int get_fobj_fd(void *file_obj)
{
	file_obj_t *fobj = file_obj;

	if (fobj->fd == -1)
		fobj->fd = open_file_obj(fobj);

	return fobj->fd;
}

static void destroy_file_obj(void *file_obj)
{
	file_obj_t *fobj = file_obj;

	if (fobj->source_fd != -1)
		close(fobj->source_fd);
	if (fobj->fd >= 0)
		fobj->ops->close(fobj);
	free(fobj->path);
	free(fobj);
}

static void __put_file_obj(file_obj_t *fobj, void *link_remap)
{
	if (--fobj->users)
		return;

	if (link_remap)
		put_link_remap(link_remap);

	destroy_file_obj(fobj);
}

void put_file_obj(void *file_obj)
{
	file_obj_t *fobj = file_obj;

	__put_file_obj(fobj, NULL);
}

void release_file_obj(void *file_obj)
{
	file_obj_t *fobj = file_obj;

	__put_file_obj(fobj, fobj->link_remap);
}

int get_file_obj(const char *path, unsigned flags, mode_t mode, int source_fd,
		 const struct replace_info_s *ri,
		 void *cb_data, int (*cb)(void *cb_data, void *new_fobj, void **res_fobj),
		 void **file_obj)
{
	file_obj_t *new_fobj = NULL, *res_fobj;
	int err;

	err = create_file_obj(path, flags, mode, source_fd, ri, &new_fobj);
	if (err)
		return err;

	err = cb(cb_data, (void *)new_fobj, (void **)&res_fobj);
	if (err)
		goto destroy_new_fobj;

	if (need_to_open_file(res_fobj)) {
		err = get_fobj_fd(res_fobj);
		if (err < 0)
			goto destroy_new_fobj;
	}

	res_fobj->users++;
	*file_obj = res_fobj;
	err = 0;

	if (new_fobj == res_fobj)
		goto exit;

destroy_new_fobj:
	destroy_file_obj(new_fobj);
exit:
	return err;
}
