#include "spfs_config.h"

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>

#include "include/util.h"
#include "context.h"
#include "include/log.h"

struct gateway_fh_s {
	struct work_mode_s *wm;
	unsigned open_flags;
	uint64_t fh;
};

static int gateway_release(const char *path, struct fuse_file_info *fi);
static int gateway_open(const char *path, struct fuse_file_info *fi);

static int gateway_opendir(const char *path, struct fuse_file_info *fi);
static int gateway_releasedir(const char *path, struct fuse_file_info *fi);

static struct work_mode_s *gateway_fh_mode(uint64_t gw_fh)
{
	return ((struct gateway_fh_s *)gw_fh)->wm;
}

static struct gateway_fh_s *gateway_pop_context(struct fuse_file_info *fi)
{
	struct gateway_fh_s *gw_fh = (struct gateway_fh_s *)fi->fh;

	fi->fh = gw_fh->fh;

	return gw_fh;
}

static void gateway_push_context(struct fuse_file_info *fi, struct gateway_fh_s *gw_fh)
{
	fi->fh = (uint64_t)gw_fh;
}

static void gateway_set_fh(struct gateway_fh_s *gw_fh, struct fuse_file_info *fi)
{
	gw_fh->fh = fi->fh;
	fi->fh = (uint64_t)gw_fh;
}

static void gateway_release_fh(struct gateway_fh_s *gw_fh)
{
	destroy_work_mode(gw_fh->wm);
	free(gw_fh);
}

static int gateway_create_fh(struct gateway_fh_s **gw_fh, unsigned open_flags)
{
	struct gateway_fh_s *fh;

	fh = malloc(sizeof(*fh));
	if (!fh)
		return -ENOMEM;

	fh->open_flags = open_flags;
	fh->wm = NULL;
	fh->fh = 0;

	*gw_fh = fh;
	return 0;
}

static char *gateway_full_path(const char *path, const struct work_mode_s *wm)
{
	if (wm->mode != SPFS_PROXY_MODE)
		return strdup(path);
	return xsprintf("%s%s", wm->proxy_dir, path);
}

inline static int gateway_stale_fh(struct fuse_file_info *fi)
{
	struct work_mode_s *wm = gateway_fh_mode(fi->fh);

	return stale_work_mode(wm->mode, wm->proxy_dir);
}

inline static int gateway_reopen_fh(const char *path, struct fuse_file_info *fi)
{
	struct gateway_fh_s *cur_fh = (struct gateway_fh_s *)fi->fh;
	struct gateway_fh_s *new_fh, tmp_fh;
	struct fuse_file_info tmp_fi = {
		/* This file info will be used to open and We care only about
		 * open flags here */
		.flags = cur_fh->open_flags,
	};
	int (*open)(const char *path, struct fuse_file_info *fi) =
		(fi->flags & O_DIRECTORY) ? gateway_opendir : gateway_open;
	int (*release)(const char *path, struct fuse_file_info *fi) =
		(fi->flags & O_DIRECTORY) ? gateway_releasedir : gateway_release;
	int err;

	pr_info("%s: reopening file handle for %s (mode: %d -> %d, proxy_dir: %s -> %s)\n",
			__func__, path,
			gateway_fh_mode(fi->fh)->mode,
			ctx_work_mode()->mode,
			gateway_fh_mode(fi->fh)->proxy_dir ? : 0,
			ctx_work_mode()->proxy_dir ? : 0);

	/* Open new fh by using temporary fi */
	err = open(path, &tmp_fi);
	if (err) {
		pr_err("%s: failed to open new file handler for %s\n",
				__func__, path);
		return err;
	}
	new_fh = (struct gateway_fh_s *)tmp_fi.fh;

	/* Here we swap contents of new fh and cur fh.
	 * The reason for this is that cur fh pointer is stored in libfuse
	 * internals, so we can't simply replace the pointer itself (original
	 * one will be returned to us on next call).
	 */
	tmp_fh = *new_fh;
	*new_fh = *cur_fh;
	*cur_fh = tmp_fh;

	/* Releasing new fh with contents of _original_ one:
	 * 1) close previous file descriptor (tmp_fi->fh->fh)
	 * 2) and release memory, used by old file handle (tmp_fi->cur_fh).
	 */
	err = release(path, &tmp_fi);
	if (err) {
		pr_err("%s: failed to release old file handler for %s\n",
				__func__, path);
		return err;
	}
	return err;
}
/* This macro is used for _any_operation, which means that context was set
 * already */
#define GATEWAY_METHOD(__func, __path, __fh, ...)				\
({										\
	int ___err = -ENOSYS;							\
	const struct fuse_operations *___ops = get_operations(__fh->wm);	\
										\
	pr_info("gateway: %s(\"%s\") = ...\n", #__func, __path);		\
										\
	if (___ops->__func) {							\
		char *___fpath;							\
										\
		___err = -ENOMEM;						\
		___fpath = gateway_full_path(__path, __fh->wm);			\
		if (___fpath)							\
			___err = ___ops->__func(___fpath, ##__VA_ARGS__);	\
		free(___fpath);							\
	}									\
	if (___err < 0)								\
		pr_err("= %d (%s)\n", ___err, strerror(-___err));		\
	else									\
		pr_info("= %d\n", ___err);					\
	___err;									\
})

/* This macro below is used for any fi-related operation as a sub-macro. */
#define GATEWAY_METHOD_FI(__func, __path, __fi, ...)				\
({										\
	struct gateway_fh_s *__gw_fh = gateway_pop_context(__fi);		\
	int __err;								\
										\
	__err = GATEWAY_METHOD(__func, __path, __gw_fh, ##__VA_ARGS__);		\
										\
	gateway_push_context(__fi, __gw_fh);					\
	__err;									\
})

/* This macro is used for all fi-related calls except:
 * open(), opendir(), create(),
 * and
 * release() and releasedir().
 * Unfortunatelly, libfuse copies fi instead of using the one, returned from
 * open() call...
 * Because of this, we can't reopen the file only once on mode change.
 * We have to open a correct file and close it instead on each time and the
 * fi-related callback is called.
 * Note: we have to _close_ the file each time, because otherwise we quickly
 * run out of file descriptors */
#define GATEWAY_METHOD_FI_RESTARTABLE(_func, _path, _fi, ...)			\
({										\
	int _err = 0;								\
										\
	do {									\
		if (gateway_stale_fh(_fi))					\
			_err = gateway_reopen_fh(_path, _fi);			\
										\
		if (!_err)							\
			_err = GATEWAY_METHOD_FI(_func, _path, _fi,		\
						 ##__VA_ARGS__);		\
	} while (_err == -ERESTARTSYS);						\
	_err;									\
})

/* This macro is used for any operation without _active_ fh (including
 * open(), opendir(), release(), releasedir() and create()).
 * Temporary fh is created on stack to fit macro calling convention */
#define GATEWAY_METHOD_FH_RESTARTABLE(_func, _path, _gw_fh, ...)		\
({										\
	int _err;								\
										\
	do {									\
		destroy_work_mode(_gw_fh->wm);					\
		_err = copy_work_mode(&_gw_fh->wm);				\
		if (!_err)							\
			_err = GATEWAY_METHOD(_func, _path, _gw_fh,		\
					      ##__VA_ARGS__);			\
	} while(_err == -ERESTARTSYS);						\
	_err;									\
})

/* This macro is used for any operation without fh.
 * Temporary fh is created on stack to fit macro calling convention */
#define GATEWAY_METHOD_RESTARTABLE(_func, _path, ...)				\
({										\
	struct gateway_fh_s __on_stack_fh = {					\
		.wm = NULL,							\
	}, *__gw_fh = &__on_stack_fh;						\
	int __err;								\
										\
	__err = GATEWAY_METHOD_FH_RESTARTABLE(_func, _path, __gw_fh,		\
					      ##__VA_ARGS__);			\
										\
	__err;									\
})


/* This macro is called for open(), opendir(), and create() callbacks */
#define GATEWAY_OPEN_RESTARTABLE(_func, _path, _fi, ...)			\
({										\
	int _err;								\
	struct gateway_fh_s *_gw_fh = NULL;					\
										\
	_err = gateway_create_fh(&_gw_fh, _fi->flags);				\
	if (_err == 0)								\
		_err = GATEWAY_METHOD_FH_RESTARTABLE(_func, _path, _gw_fh,	\
						     ##__VA_ARGS__);		\
	else									\
		pr_err("%s: failed to create gateway context for %s\n",		\
			__func__, _path);					\
	if (_err)								\
		gateway_release_fh(_gw_fh);					\
	else									\
		gateway_set_fh(_gw_fh, _fi);					\
	_err;									\
})

/* This macro is called for link(), symlink() and rename(), where there are two
 * paths to fix in case of PROXY mode. */
#define GATEWAY_LINK_RESTARTABLE(_func, _f, _s)					\
({										\
	char *_fs;								\
	int _err = -ENOMEM;							\
										\
	_fs = gateway_full_path(_s, ctx_work_mode());				\
	if (_fs)								\
		_err = GATEWAY_METHOD_RESTARTABLE(_func, _f, _fs);		\
	free(_fs);								\
	_err;									\
})

/* This macro below is used for release() and releasedir(), because in this
 * case only original fh matters.
 */
#define GATEWAY_RELEASE(_func, _path, _fi, ...)					\
({										\
	int _err;								\
										\
	_err = GATEWAY_METHOD_FI(_func, _path, _fi, ##__VA_ARGS__);		\
	if (!_err)								\
		gateway_release_fh((struct gateway_fh_s *)_fi->fh);		\
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
	return GATEWAY_LINK_RESTARTABLE(symlink, to, from);
}

static int gateway_rename(const char *from, const char *to)
{
	return GATEWAY_LINK_RESTARTABLE(rename, from, to);
}

static int gateway_link(const char *from, const char *to)
{
	return GATEWAY_LINK_RESTARTABLE(link, from, to);
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
	return GATEWAY_RELEASE(release, path, fi,
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
	return GATEWAY_RELEASE(releasedir, path, fi,
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
