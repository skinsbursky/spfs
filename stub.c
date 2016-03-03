#define FUSE_USE_VERSION 26

#include "config.h"

#include <fuse.h>

#include "context.h"

static int stub_getattr(const char *path, struct stat *stbuf)
{
	if (!strcmp(path, "/")) {
		/* This is a very specific situation.
		 * In some cases (say "ls -l /") stat will be called on fuse
		 * root. It doens't make sense to put the caller to sleep.
		 * Let's return some directory stat instead. */
		*stbuf = get_context()->root.stat;
		return 0;
	}
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_readlink(const char *path, char *buf, size_t size)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_mknod(const char *path, mode_t mode, dev_t rdev)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_mkdir(const char *path, mode_t mode)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_unlink(const char *path)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_rmdir(const char *path)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_symlink(const char *to, const char *from)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_rename(const char *from, const char *to)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_link(const char *from, const char *to)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_chmod(const char *path, mode_t mode)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_chown(const char *path, uid_t uid, gid_t gid)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_truncate(const char *path, off_t size)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_open(const char *path, struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_read(const char *path, char *buf, size_t size, off_t offset,
			struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_write(const char *path, const char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_statfs(const char *path, struct statvfs *stbuf)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_flush(const char *path, struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_release(const char *path, struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_fsync(const char *path, int isdatasync,
		struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_setxattr(const char *path, const char *name, const char *value,
			    size_t size, int flags)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_getxattr(const char *path, const char *name, char *value,
			    size_t size)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_listxattr(const char *path, char *list, size_t size)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_removexattr(const char *path, const char *name)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_opendir(const char *path, struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			   off_t offset, struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_releasedir(const char *path, struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_access(const char *path, int mask)
{
	return wait_mode_change(FUSE_STUB_MODE);

}

static int stub_create(const char *path, mode_t mode,
		struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_ftruncate(const char *path, off_t offset,
		struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_fgetattr(const char *path, struct stat *stbuf,
			    struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_lock(const char *path, struct fuse_file_info *fi, int cmd,
			struct flock *lock)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_utimens(const char *path, const struct timespec tv[2])
{
	return wait_mode_change(FUSE_STUB_MODE);
}
#if 0
static int stub_fsyncdir(const char *path, int isdatasync,
			    struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_bmap(const char *path, size_t blocksize, uint64_t *idx)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_ioctl(const char *path, int cmd, void *arg,
			 struct fuse_file_info *fi, unsigned int flags,
			 void *ctx)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_poll(const char *path, struct fuse_file_info *fi,
			struct fuse_pollhandle *ph, unsigned *reventsp)
{
	return wait_mode_change(FUSE_STUB_MODE);
}
#endif
static int stub_write_buf(const char *path, struct fuse_bufvec *buf,
			     off_t off, struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_read_buf(const char *path, struct fuse_bufvec **bufp,
			    size_t size, off_t off, struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_flock(const char *path, struct fuse_file_info *fi, int op)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

static int stub_fallocate(const char *path, int mode, off_t offset,
			     off_t lenght, struct fuse_file_info *fi)
{
	return wait_mode_change(FUSE_STUB_MODE);
}

struct fuse_operations stub_operations = {
	.getattr	= stub_getattr,
	.fgetattr	= stub_fgetattr,
	.access		= stub_access,
	.readlink	= stub_readlink,
	.opendir	= stub_opendir,
	.readdir	= stub_readdir,
	.releasedir	= stub_releasedir,
	.mknod		= stub_mknod,
	.mkdir		= stub_mkdir,
	.symlink	= stub_symlink,
	.unlink		= stub_unlink,
	.rmdir		= stub_rmdir,
	.rename		= stub_rename,
	.link		= stub_link,
	.chmod		= stub_chmod,
	.chown		= stub_chown,
	.truncate	= stub_truncate,
	.ftruncate	= stub_ftruncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= stub_utimens,
#endif
	.create		= stub_create,
	.open		= stub_open,
	.read		= stub_read,
	.read_buf	= stub_read_buf,
	.write		= stub_write,
	.write_buf	= stub_write_buf,
	.statfs		= stub_statfs,
	.flush		= stub_flush,
	.release	= stub_release,
	.fsync		= stub_fsync,
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= stub_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= stub_setxattr,
	.getxattr	= stub_getxattr,
	.listxattr	= stub_listxattr,
	.removexattr	= stub_removexattr,
#endif
	.lock		= stub_lock,
	.flock		= stub_flock,

	.flag_nullpath_ok = 1,
#if HAVE_UTIMENSAT
	.flag_utime_omit_ok = 1,
#endif
};
