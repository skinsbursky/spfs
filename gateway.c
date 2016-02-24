#include "config.h"

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"
#include "context.h"
#include "log.h"

struct gateway_fh_s {
	unsigned mode;
	uint64_t fh;
};

static int gateway_release(const char *path, struct fuse_file_info *fi);
static int gateway_open(const char *path, struct fuse_file_info *fi);

static int gateway_opendir(const char *path, struct fuse_file_info *fi);
static int gateway_releasedir(const char *path, struct fuse_file_info *fi);

static uint64_t gateway_fh_data(uint64_t gw_fh)
{
	return ((struct gateway_fh_s *)gw_fh)->fh;
}

static unsigned gateway_fh_mode(uint64_t gw_fh)
{
	return ((struct gateway_fh_s *)gw_fh)->mode;
}

static uint64_t gateway_pop_context(struct fuse_file_info *fi)
{
	uint64_t gw_fh = fi->fh;

	fi->fh = gateway_fh_data(fi->fh);

	return gw_fh;
}

static void gateway_push_context(struct fuse_file_info *fi, uint64_t gw_fh)
{
	fi->fh = gw_fh;
}

static void gateway_set_fh(uint64_t gw_fh, struct fuse_file_info *fi)
{
	((struct gateway_fh_s *)gw_fh)->fh = fi->fh;
	fi->fh = gw_fh;
}

static void gateway_release_fh(uint64_t gw_fh)
{
	free((struct gateway_fh_s *)gw_fh);
}

static int gateway_create_fh(uint64_t *gw_fh)
{
	struct gateway_fh_s *fh;

	fh = malloc(sizeof(*fh));
	if (!fh)
		return -ENOMEM;

	fh->mode = get_context()->mode;
	*gw_fh = (uint64_t)fh;
	return 0;
}

static char *gateway_fix_path(const char *path)
{
	const struct context_data_s *ctx = get_context();

	if (ctx->mode != FUSE_PROXY_MODE)
		return strdup(path);
	return xsprintf("%s%s", ctx->proxy_dir, path);
}

static int gateway_reopen_fh(const char *path, struct fuse_file_info *fi)
{
	int err = 0;

	if (gateway_fh_mode(fi->fh) != get_context()->mode) {
		int (*open)(const char *path, struct fuse_file_info *fi);
		int (*release)(const char *path, struct fuse_file_info *fi);

		open = (fi->flags & O_DIRECTORY) ? gateway_opendir : gateway_open;
		release = (fi->flags & O_DIRECTORY) ? gateway_releasedir : gateway_release;

		/* File handle is stale. Need to reopen. */
		pr_info("%s: reopening file handle for %s (mode: %d -> %d)\n",
				__func__, path, gateway_fh_mode(fi->fh),
				get_context()->mode);

		err = release(path, fi);
		if (err)
			pr_err("%s: failed to release fd for %s\n", __func__, path);

		err = open(path, fi);
		if (err)
			pr_err("%s: failed to reopen file handler for %s\n",
					__func__, path);
	}
	return err;
}

#define GATEWAY_METHOD(__name, __path, ...)					\
({										\
	int ___err = -ENOSYS;							\
	const struct fuse_operations *___ops = get_operations();		\
										\
	pr_debug("%s: %s\n", __func__, __path);					\
	if (___ops->__name) {							\
		char *___fpath;							\
										\
		___err = -ENOMEM;						\
		___fpath = gateway_fix_path(__path);				\
		if (___fpath)							\
			___err = ___ops->__name(___fpath, ##__VA_ARGS__);	\
		free(___fpath);							\
	}									\
	___err;									\
})

#define GATEWAY_METHOD_FH(__func, __path, __fi, ...)				\
({										\
	uint64_t __gw_fh = gateway_pop_context(__fi);				\
	int __err;								\
										\
	__err = GATEWAY_METHOD(__func, __path, ##__VA_ARGS__);			\
										\
	gateway_push_context(__fi, __gw_fh);					\
	__err;									\
})

#define GATEWAY_METHOD_RESTARTABLE(_func, _path, ...)				\
({										\
	int _err;								\
	do {									\
		_err = GATEWAY_METHOD(_func, _path, ##__VA_ARGS__);		\
	} while(_err == -ERESTARTSYS);						\
	_err;									\
})

#define GATEWAY_METHOD_FI_RESTARTABLE(_func, _path, _fi, ...)			\
({										\
	int _err;								\
										\
	_err = gateway_reopen_fh(_path, _fi);					\
	if (_err == 0) {							\
		do {								\
			_err = GATEWAY_METHOD_FH(_func, _path, _fi,		\
						 ##__VA_ARGS__);		\
			if (_err == -ERESTARTSYS) {				\
				int __err;					\
										\
				__err = gateway_reopen_fh(_path, _fi);		\
				if (__err)					\
					_err = __err;				\
			}							\
		} while(_err == -ERESTARTSYS);					\
	}									\
	_err;									\
})

#define GATEWAY_OPEN_RESTARTABLE(_func, _path, _fi, ...)			\
({										\
	int _err;								\
	uint64_t _gw_fh;							\
										\
	_err = gateway_create_fh(&_gw_fh);					\
	if (_err == 0) {							\
		_err = GATEWAY_METHOD_RESTARTABLE(_func, _path,			\
						  ##__VA_ARGS__);		\
		if (_err)							\
			gateway_release_fh(_gw_fh);				\
		else								\
			gateway_set_fh(_gw_fh, _fi);				\
	} else									\
		pr_err("%s: failed to create gateway context for %s\n",		\
			__func__, _path);					\
	_err;									\
})

#define GATEWAY_POINT_RESTARTABLE(_func, _f, _s)				\
({										\
	char *_ss;								\
	int _err = -ENOMEM;							\
										\
	_ss = gateway_fix_path(_s);						\
	if (_ss)								\
		_err = GATEWAY_METHOD_RESTARTABLE(_func, _f, _ss);		\
	free(_ss);								\
	_err;									\
})

static int gateway_getattr(const char *path, struct stat *stbuf)
{
	return GATEWAY_METHOD_RESTARTABLE(getattr, path, stbuf);
}

static int gateway_readlink(const char *path, char *buf, size_t size)
{
	return GATEWAY_METHOD_RESTARTABLE(readlink, path, buf, size);
}

static int gateway_mknod(const char *path, mode_t mode, dev_t rdev)
{
	return GATEWAY_METHOD_RESTARTABLE(mknod, path, mode, rdev);
}

static int gateway_mkdir(const char *path, mode_t mode)
{
	return GATEWAY_METHOD_RESTARTABLE(mkdir, path, mode);
}

static int gateway_unlink(const char *path)
{
	return GATEWAY_METHOD_RESTARTABLE(unlink, path);
}

static int gateway_rmdir(const char *path)
{
	return GATEWAY_METHOD_RESTARTABLE(rmdir, path);
}

static int gateway_symlink(const char *to, const char *from)
{
	return GATEWAY_POINT_RESTARTABLE(link, to, from);
}

static int gateway_rename(const char *from, const char *to)
{
	return GATEWAY_POINT_RESTARTABLE(link, from, to);
}

static int gateway_link(const char *from, const char *to)
{
	return GATEWAY_POINT_RESTARTABLE(link, from, to);
}

static int gateway_chmod(const char *path, mode_t mode)
{
	return GATEWAY_METHOD_RESTARTABLE(chmod, path, mode);
}

static int gateway_chown(const char *path, uid_t uid, gid_t gid)
{
	return GATEWAY_METHOD_RESTARTABLE(chown, path, uid, gid);
}

static int gateway_truncate(const char *path, off_t size)
{
	return GATEWAY_METHOD_RESTARTABLE(truncate, path, size);
}

static int gateway_read(const char *path, char *buf, size_t size, off_t offset,
			struct fuse_file_info *fi)
{
	return GATEWAY_METHOD_FI_RESTARTABLE(read, path, fi,
					     buf, size, offset, fi);
}

static int gateway_write(const char *path, const char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
	return GATEWAY_METHOD_FI_RESTARTABLE(write, path, fi,
					     buf, size, offset, fi);
}

static int gateway_statfs(const char *path, struct statvfs *stbuf)
{
	return GATEWAY_METHOD_RESTARTABLE(statfs, path, stbuf);
}

static int gateway_flush(const char *path, struct fuse_file_info *fi)
{
	return GATEWAY_METHOD_FI_RESTARTABLE(flush, path, fi,
					     fi);
}

static int gateway_fsync(const char *path, int isdatasync,
		struct fuse_file_info *fi)
{
	return GATEWAY_METHOD_FI_RESTARTABLE(fsync, path, fi,
					     isdatasync, fi);
}

static int gateway_setxattr(const char *path, const char *name, const char *value,
			    size_t size, int flags)
{
	return GATEWAY_METHOD_RESTARTABLE(setxattr, path, name, value, size, flags);
}

static int gateway_getxattr(const char *path, const char *name, char *value,
			    size_t size)
{
	return GATEWAY_METHOD_RESTARTABLE(getxattr, path, name, value, size);
}

static int gateway_listxattr(const char *path, char *list, size_t size)
{
	return GATEWAY_METHOD_RESTARTABLE(listxattr, path, list, size);
}

static int gateway_removexattr(const char *path, const char *name)
{
	return GATEWAY_METHOD_RESTARTABLE(removexattr, path, name);
}

static int gateway_release(const char *path, struct fuse_file_info *fi)
{
	return GATEWAY_METHOD_FH(release, path, fi,
				 fi);
}

static int gateway_open(const char *path, struct fuse_file_info *fi)
{
	return GATEWAY_OPEN_RESTARTABLE(open, path, fi,
					fi);
}

static int gateway_opendir(const char *path, struct fuse_file_info *fi)
{
	return GATEWAY_OPEN_RESTARTABLE(opendir, path, fi,
					fi);
}

static int gateway_create(const char *path, mode_t mode,
		struct fuse_file_info *fi)
{
	return GATEWAY_OPEN_RESTARTABLE(create, path, fi,
					mode, fi);
}

static int gateway_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			   off_t offset, struct fuse_file_info *fi)
{
	return GATEWAY_METHOD_FI_RESTARTABLE(readdir, path, fi,
					     buf, filler, offset, fi);
}

static int gateway_releasedir(const char *path, struct fuse_file_info *fi)
{
	return GATEWAY_METHOD_FI_RESTARTABLE(releasedir, path, fi,
					     fi);
}

#if 0
static int gateway_fsyncdir(const char *path, int isdatasync,
			    struct fuse_file_info *fi)
{
	return GATEWAY_METHOD_RESTARTABLE(fsyncdir, path, isdatasync, fi);
}
#endif

static int gateway_access(const char *path, int mask)
{
	return GATEWAY_METHOD_RESTARTABLE(access, path, mask);
}

static int gateway_ftruncate(const char *path, off_t offset,
		struct fuse_file_info *fi)
{
	return GATEWAY_METHOD_FI_RESTARTABLE(ftruncate, path, fi,
					     offset, fi);
}

static int gateway_fgetattr(const char *path, struct stat *stbuf,
			    struct fuse_file_info *fi)
{
	return GATEWAY_METHOD_FI_RESTARTABLE(fgetattr, path, fi,
					     stbuf, fi);
}

static int gateway_lock(const char *path, struct fuse_file_info *fi, int cmd,
			struct flock *lock)
{
	return GATEWAY_METHOD_FI_RESTARTABLE(lock, path, fi,
					     fi, cmd, lock);
}

static int gateway_utimens(const char *path, const struct timespec tv[2])
{
	return GATEWAY_METHOD_RESTARTABLE(utimens, path, tv);
}
#if 0
static int gateway_bmap(const char *path, size_t blocksize, uint64_t *idx)
{
	return GATEWAY_METHOD_RESTARTABLE(bmap, path, blocksize, idx);
}

static int gateway_ioctl(const char *path, int cmd, void *arg,
			 struct fuse_file_info *fi, unsigned int flags,
			 void *ctx)
{
	return GATEWAY_METHOD_RESTARTABLE(ioctl, path, cmd, arg, fi, flags, ctx);
}

static int gateway_poll(const char *path, struct fuse_file_info *fi,
			struct fuse_pollhandle *ph, unsigned *reventsp)
{
	return GATEWAY_METHOD_RESTARTABLE(poll, path, fi, ph, reventsp);
}

static int gateway_write_buf(const char *path, struct fuse_bufvec *buf,
			     off_t off, struct fuse_file_info *fi)
{
	return GATEWAY_METHOD_RESTARTABLE(write_buf, path, buf, off, fi->fh);
}

static int gateway_read_buf(const char *path, struct fuse_bufvec **bufp,
			    size_t size, off_t off, struct fuse_file_info *fi)
{
	return GATEWAY_METHOD_RESTARTABLE(read_buf, path, bufp, size, off, fi->fh);
}
#endif
static int gateway_flock(const char *path, struct fuse_file_info *fi, int op)
{
	return GATEWAY_METHOD_FI_RESTARTABLE(flock, path, fi,
					     fi, op);
}

static int gateway_fallocate(const char *path, int mode, off_t offset,
			     off_t lenght, struct fuse_file_info *fi)
{
	return GATEWAY_METHOD_FI_RESTARTABLE(fallocate, path, fi,
					     mode, offset, lenght, fi);
}

struct fuse_operations gateway_operations = {
	.getattr	= gateway_getattr,
	.fgetattr	= gateway_fgetattr,
	.access		= gateway_access,
	.readlink	= gateway_readlink,
	.opendir	= gateway_opendir,
	.readdir	= gateway_readdir,
	.releasedir	= gateway_releasedir,
	.mknod		= gateway_mknod,
	.mkdir		= gateway_mkdir,
	.symlink	= gateway_symlink,
	.unlink		= gateway_unlink,
	.rmdir		= gateway_rmdir,
	.rename		= gateway_rename,
	.link		= gateway_link,
	.chmod		= gateway_chmod,
	.chown		= gateway_chown,
	.truncate	= gateway_truncate,
	.ftruncate	= gateway_ftruncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= gateway_utimens,
#endif
	.create		= gateway_create,
	.open		= gateway_open,
	.read		= gateway_read,
//	.read_buf	= gateway_read_buf,
	.write		= gateway_write,
//	.write_buf	= gateway_write_buf,
	.statfs		= gateway_statfs,
	.flush		= gateway_flush,
	.release	= gateway_release,
	.fsync		= gateway_fsync,
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= gateway_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= gateway_setxattr,
	.getxattr	= gateway_getxattr,
	.listxattr	= gateway_listxattr,
	.removexattr	= gateway_removexattr,
#endif
	.lock		= gateway_lock,
	.flock		= gateway_flock,

	.flag_nullpath_ok = 1,
#if HAVE_UTIMENSAT
	.flag_utime_omit_ok = 1,
#endif
};
