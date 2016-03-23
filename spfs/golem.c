#include "spfs_config.h"

#include <fuse.h>

#include "include/context.h"
#include "include/log.h"

const struct dentry_info_s *find_dentry_info(struct context_data_s *ctx, const char *path)
{
	const struct dentry_info_s *parent = NULL;
	const char *dentry, *slash;

	slash = path;
	parent = &ctx->root;

	if (pthread_mutex_lock(&ctx->root_lock)) {
		pr_err("%s: failed to lock root\n", __func__);
		return NULL;
	}

	while (1) {
		const struct dentry_info_s *child;
		int found = 0, len;

		dentry = slash + 1;
		if (strlen(dentry) == 0)
			break;

		slash = strchr(dentry, '/');
		if (slash)
			len = slash - dentry;
		else
			len = strlen(dentry);

		list_for_each_entry(child, &parent->children, siblings) {
			if (!strncmp(child->name, dentry, len)) {
				parent = child;
				found = 1;
				break;
			}
		}
		if (!found) {
			parent = NULL;
			break;
		}
		if (!slash)
			break;

	}
	pthread_mutex_unlock(&ctx->root_lock);
	return parent;
}

static int golem_getattr(const char *path, struct stat *stbuf)
{
	struct context_data_s *ctx = get_context();
	const struct dentry_info_s *info;

	pr_debug("%s: searching dentry for path %s\n", __func__, path);

	info = find_dentry_info(ctx, path);
	if (!info) {
		pr_debug("%s: dentry for path %s wasn't found\n", __func__, path);
		return -ENOENT;
	}

	pr_debug("%s: return stat for path %s\n", __func__, path);

	memcpy(stbuf, &info->stat, sizeof(info->stat));
	return 0;
}

static int golem_readlink(const char *path, char *buf, size_t size)
{
	return -ENOSYS;
}

static int golem_mknod(const char *path, mode_t mode, dev_t rdev)
{
	return -ENOSYS;
}

static int golem_mkdir(const char *path, mode_t mode)
{
	return -ENOSYS;
}

static int golem_unlink(const char *path)
{
	return -ENOSYS;
}

static int golem_rmdir(const char *path)
{
	return -ENOSYS;
}

static int golem_symlink(const char *to, const char *from)
{
	return -ENOSYS;
}

static int golem_rename(const char *from, const char *to)
{
	return -ENOSYS;
}

static int golem_link(const char *from, const char *to)
{
	return -ENOSYS;
}

static int golem_chmod(const char *path, mode_t mode)
{
	return -ENOSYS;
}

static int golem_chown(const char *path, uid_t uid, gid_t gid)
{
	return -ENOSYS;
}

static int golem_truncate(const char *path, off_t size)
{
	return -ENOSYS;
}

static int golem_open(const char *path, struct fuse_file_info *fi)
{
	struct context_data_s *ctx = get_context();
	const struct dentry_info_s *info;

	info = find_dentry_info(ctx, path);
	if (!info)
		return -ENOENT;

	pr_debug("%s: return pointer to %s\n", __func__, info->name);

	fi->fh = (unsigned long)info;

	return 0;
}

static int golem_read(const char *path, char *buf, size_t size, off_t offset,
			struct fuse_file_info *fi)
{
	return size;
}

static int golem_write(const char *path, const char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
	return -ENOSYS;
}

static int golem_statfs(const char *path, struct statvfs *stbuf)
{
	return -ENOSYS;
}

static int golem_flush(const char *path, struct fuse_file_info *fi)
{
	return -ENOSYS;
}

static int golem_release(const char *path, struct fuse_file_info *fi)
{
	fi->fh = 0;
	return 0;
}

static int golem_fsync(const char *path, int isdatasync,
		struct fuse_file_info *fi)
{
	return -ENOSYS;
}

static int golem_setxattr(const char *path, const char *name, const char *value,
			    size_t size, int flags)
{
	return -ENOSYS;
}

static int golem_getxattr(const char *path, const char *name, char *value,
			    size_t size)
{
	return -ENODATA;
}

static int golem_listxattr(const char *path, char *list, size_t size)
{
	return -ENOSYS;
}

static int golem_removexattr(const char *path, const char *name)
{
	return -ENOSYS;
}

static int golem_opendir(const char *path, struct fuse_file_info *fi)
{
	struct context_data_s *ctx = get_context();
	const struct dentry_info_s *info;

	info = find_dentry_info(ctx, path);
	if (!info)
		return -ENOENT;

	pr_debug("%s: return pointer to %s\n", __func__, info->name);

	fi->fh = (unsigned long)info;

	return 0;
}

static int golem_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			   off_t offset, struct fuse_file_info *fi)
{
	const struct dentry_info_s *info;
	const struct dentry_info_s *child;

	info = (struct dentry_info_s *)fi->fh;
	if (!info)
		return -ENOENT;

	pr_debug("%s: read dir %s, offset: %ld\n", __func__, info->name, offset);
	if (offset)
		return -ENOSYS;

	list_for_each_entry(child, &info->children, siblings) {
                if (filler(buf, child->name, &child->stat, 0))
			                        break;
	}

	return 0;
}

static int golem_releasedir(const char *path, struct fuse_file_info *fi)
{
	fi->fh = 0;
	return 0;
}

#if 0
static int golem_fsyncdir(const char *path, int isdatasync,
			    struct fuse_file_info *fi)
{
	return -ENOSYS;
}

static void *golem_init(struct fuse_conn_info *conn)
{
	struct fuse_context *ctx;
	struct golem_data_s *ctx = get_context();

	fuse_log = ctx->log;

	pr_debug("%s: %ld\n", __func__, syscall(SYS_gettid));
	pr_debug("%s: ctx: %p\n", __func__, ctx);
	pr_debug("%s: ctx->private_data: %p\n", __func__, ctx->private_data);
	signal(SIGUSR1, handle_signal);
	return ctx->private_data;
}

static void golem_destroy(void *private_data)
{
	pr_debug("%s: %d\n", __func__, getpid());
}
#endif
static int golem_access(const char *path, int mask)
{
	return 0;
}

static int golem_create(const char *path, mode_t mode,
		struct fuse_file_info *fi)
{
	return -ENOSYS;
}

static int golem_ftruncate(const char *path, off_t offset,
		struct fuse_file_info *fi)
{
	return -ENOSYS;
}

static int golem_fgetattr(const char *path, struct stat *stbuf,
			    struct fuse_file_info *fi)
{
	return -ENOSYS;
}

static int golem_lock(const char *path, struct fuse_file_info *fi, int cmd,
			struct flock *lock)
{
	return -ENOSYS;
}

static int golem_utimens(const char *path, const struct timespec tv[2])
{
	return -ENOSYS;
}
#if 0
static int golem_bmap(const char *path, size_t blocksize, uint64_t *idx)
{
	return -ENOSYS;
}

static int golem_ioctl(const char *path, int cmd, void *arg,
			 struct fuse_file_info *fi, unsigned int flags,
			 void *ctx)
{
	return -ENOSYS;
}

static int golem_poll(const char *path, struct fuse_file_info *fi,
			struct fuse_pollhandle *ph, unsigned *reventsp)
{
	return -ENOSYS;
}
#endif
static int golem_write_buf(const char *path, struct fuse_bufvec *buf,
			     off_t off, struct fuse_file_info *fi)
{
	return -ENOSYS;
}

static int golem_read_buf(const char *path, struct fuse_bufvec **bufp,
			    size_t size, off_t off, struct fuse_file_info *fi)
{
	return -ENOSYS;
}

static int golem_flock(const char *path, struct fuse_file_info *fi, int op)
{
	return -ENOSYS;
}

static int golem_fallocate(const char *path, int mode, off_t offset,
			     off_t lenght, struct fuse_file_info *fi)
{
	return -ENOSYS;
}

struct fuse_operations golem_operations = {
	.getattr	= golem_getattr,
	.fgetattr	= golem_fgetattr,
	.access		= golem_access,
	.readlink	= golem_readlink,
	.opendir	= golem_opendir,
	.readdir	= golem_readdir,
	.releasedir	= golem_releasedir,
	.mknod		= golem_mknod,
	.mkdir		= golem_mkdir,
	.symlink	= golem_symlink,
	.unlink		= golem_unlink,
	.rmdir		= golem_rmdir,
	.rename		= golem_rename,
	.link		= golem_link,
	.chmod		= golem_chmod,
	.chown		= golem_chown,
	.truncate	= golem_truncate,
	.ftruncate	= golem_ftruncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= golem_utimens,
#endif
	.create		= golem_create,
	.open		= golem_open,
	.read		= golem_read,
	.read_buf	= golem_read_buf,
	.write		= golem_write,
	.write_buf	= golem_write_buf,
	.statfs		= golem_statfs,
	.flush		= golem_flush,
	.release	= golem_release,
	.fsync		= golem_fsync,
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= golem_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= golem_setxattr,
	.getxattr	= golem_getxattr,
	.listxattr	= golem_listxattr,
	.removexattr	= golem_removexattr,
#endif
	.lock		= golem_lock,
	.flock		= golem_flock,

	.flag_nullpath_ok = 1,
#if HAVE_UTIMENSAT
	.flag_utime_omit_ok = 1,
#endif
};
