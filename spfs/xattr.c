#include <stdlib.h>
#include <search.h>
#include <semaphore.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include "include/list.h"
#include "include/log.h"

#include "xattr.h"

struct file_xattr_s {
	struct list_head list;
	char		*name;
	void		*value;
	size_t		size;
};

struct xattr_tree_s {
	struct list_head	xattrs;
	int			users;
};

struct file_xattr_tree_s {
	char			*path;
	struct xattr_tree_s	*tree;
};

static void destroy_xattr(struct file_xattr_s *fx)
{
	free(fx->value);
	free(fx->name);
	free(fx);
}

static int set_xattr_value(struct file_xattr_s *fx, const void *value, size_t size)
{
	char *new;

	new = malloc(size);
	if (!new) {
		pr_err("failed to allocate\n");
		return -ENOSPC;
	}
	memcpy(new, value, size);

	fx->value = new;
	fx->size = size;
	return 0;
}

static int update_xattr_value(struct file_xattr_s *fx, const void *value, size_t size)
{
	void *old_value = fx->value;
	int err;

	err = set_xattr_value(fx, value, size);
	if (err)
		return err;

	if (old_value)
		free(old_value);

	return 0;
}

static struct file_xattr_s *create_xattr(const char *name,
					 const void *value, size_t size)
{
	struct file_xattr_s *fx;

	fx = malloc(sizeof(*fx));
	if (!fx) {
		pr_err("failed to allocate\n");
		return NULL;
	}

	fx->name = strdup(name);
	if (!fx->name) {
		pr_err("failed to duplicate\n");
		goto free_fx;
	}

	if (set_xattr_value(fx, value, size))
		goto free_fx_name;

	return fx;

free_fx_name:
	free(fx->name);
free_fx:
	free(fx);
	return NULL;
}

static struct file_xattr_s *find_xattr(const struct xattr_tree_s *tree,
					   const char *name)
{
	struct file_xattr_s *fx;

	list_for_each_entry(fx, &tree->xattrs, list) {
		if (!strcmp(fx->name, name))
			return fx;
	}
	return NULL;
}

static int add_xattr(struct xattr_tree_s *tree, struct file_xattr_s *new_fx)
{
	list_add_tail(&new_fx->list, &tree->xattrs);
	return 0;
}

static void del_xattr(struct xattr_tree_s *tree, struct file_xattr_s *fx)
{
	list_del(&fx->list);
}

static ssize_t tree_getxattr(struct xattr_tree_s *tree, const char *name,
			     void *value, size_t size)
{
	struct file_xattr_s *fx;

	fx = find_xattr(tree, name);
	if (!fx)
		return -ENODATA;

	if (size < fx->size)
		return -ERANGE;

	memcpy(value, fx->value, fx->size);
	return fx->size;
}

static int tree_setxattr(struct xattr_tree_s *tree, const char *path,
			 const char *name, const void *value, size_t size,
			 int flags)
{
	struct file_xattr_s *fx = NULL, *found_fx;
	int err;

	found_fx = find_xattr(tree, name);

	switch (flags) {
		case XATTR_CREATE:
			if (found_fx)
				return -EEXIST;
			break;
		case XATTR_REPLACE:
			if (!found_fx)
				return -ENODATA;
		default:
			fx = found_fx;
			break;
	}

	if (!fx) {
		fx = create_xattr(name, value, size);
		if (!fx)
			return -ENOSPC;
		err = add_xattr(tree, fx);
		if (!err)
			pr_debug("added xattr %s with value %s to file %s\n",
					name, value, path);
	} else {
		err = update_xattr_value(fx, value, size);
		if (!err)
			pr_debug("updated xattr %s with value %s of file %s\n",
					fx->name, value, path);
	}

	return err;
}

static int tree_removexattr(struct xattr_tree_s *tree, const char *name)
{
	struct file_xattr_s *fx;

	fx = find_xattr(tree, name);
	if (!fx)
		return -ENODATA;

	del_xattr(tree, fx);
	destroy_xattr(fx);
	return 0;
}

static int tree_listxattr(struct xattr_tree_s *tree, char *list, size_t size)
{
	struct file_xattr_s *fx;
	char *p = list;

	list_for_each_entry(fx, &tree->xattrs, list) {
		if (list + size > p + fx->size)
			return -ERANGE;
		memcpy(p, fx->value, fx->size);
		p += fx->size;
	}
	return p - list;
}

static void destroy_xattr_tree(struct xattr_tree_s *tree)
{
	struct file_xattr_s *fx, *tmp;

	list_for_each_entry_safe(fx, tmp, &tree->xattrs, list) {
		destroy_xattr(fx);
	}
	free(tree);
}

static bool empty_xattr_tree(const struct xattr_tree_s *tree)
{
	return list_empty(&tree->xattrs);
}

static struct xattr_tree_s *create_xattr_tree(void)
{
	struct xattr_tree_s *tree;

	tree = malloc(sizeof(*tree));
	if (!tree) {
		pr_err("failed to allocate\n");
		return NULL;
	}
	tree->users = 1;
	INIT_LIST_HEAD(&tree->xattrs);

	return tree;
}

static void put_xattr_tree(struct xattr_tree_s *tree)
{
	if (--tree->users)
		return;

	destroy_xattr_tree(tree);
}

static struct xattr_tree_s *get_xattr_tree(struct xattr_tree_s *tree)
{
	tree->users++;
	return tree;
}

static struct file_xattr_tree_s *create_file_xattr_tree(const char *path, struct xattr_tree_s *tree)
{
	struct file_xattr_tree_s *fxt;

	fxt = malloc(sizeof(*fxt));
	if (!fxt) {
		pr_err("failed to allocate\n");
		return NULL;
	}
	fxt->path = strdup(path);
	if (!fxt->path)
		goto free_fxt;

	if (tree)
		tree = get_xattr_tree(tree);
	else
		tree = create_xattr_tree();
	if (!tree)
		goto free_fxt_path;

	fxt->tree = tree;
	INIT_LIST_HEAD(&tree->xattrs);

	return fxt;

free_fxt_path:
	free(fxt->path);
free_fxt:
	free(fxt);
	return NULL;
}

void destroy_file_xattr_tree(struct file_xattr_tree_s *fxt)
{
	put_xattr_tree(fxt->tree);
	free(fxt->path);
	free(fxt);
}

static pthread_mutex_t files_tree_lock = PTHREAD_MUTEX_INITIALIZER;
static void *files_tree_root = NULL;

static int compare_fxt(const void *a, const void *b)
{
	const struct file_xattr_tree_s *f = a, *s = b;

	return strcmp(f->path, s->path);
}

static struct file_xattr_tree_s *find_file_xattr_tree(const char *path)
{
	const struct file_xattr_tree_s cookie = {
		.path = (char *)path,
	};
	struct file_xattr_tree_s **found_fxt;

	found_fxt = tfind(&cookie, &files_tree_root, compare_fxt);

	return found_fxt ? *found_fxt : NULL;
}


static struct file_xattr_tree_s *search_file_xattr_tree(const char *path)
{
	struct file_xattr_tree_s *new_fxt, **found_fxt;

	new_fxt = create_file_xattr_tree(path, NULL);
	if (!new_fxt)
		return NULL;

	found_fxt = tsearch(new_fxt, &files_tree_root, compare_fxt);
	if (!found_fxt)
		return NULL;

	if (*found_fxt != new_fxt)
		destroy_file_xattr_tree(new_fxt);
	else
		pr_debug("added xattr tree for %s\n", path);

	return *found_fxt;
}

static void remove_file_xattr_tree(struct file_xattr_tree_s *fxt)
{
	(void)tdelete(fxt, &files_tree_root, compare_fxt);
}

int spfs_setxattr(const char *path, const char *name, const void *value,
		  size_t size, int flags)
{
	int err;
	struct file_xattr_tree_s *fxt;

	err = pthread_mutex_lock(&files_tree_lock);
	if (err) {
		pr_err("%s: failed to lock xattr tree: %d\n", __func__, err);
		return -err;
	}

	fxt = search_file_xattr_tree(path);
	if (!fxt) {
		err = -ENOSPC;
		goto unlock;
	}

	err = tree_setxattr(fxt->tree, fxt->path, name, value, size, flags);

unlock:
	if (pthread_mutex_unlock(&files_tree_lock))
		pr_err("%s: failed to unlock xattr tree: %d\n", __func__, err);
	return err;
}

int spfs_removexattr(const char *path, const char *name)
{
	int err;
	struct file_xattr_tree_s *fxt;

	err = pthread_mutex_lock(&files_tree_lock);
	if (err) {
		pr_err("%s: failed to lock xattr tree: %d\n", __func__, err);
		return -err;
	}

	fxt = find_file_xattr_tree(path);
	if (!fxt) {
		err = -ENODATA;
		goto unlock;
	}

	err = tree_removexattr(fxt->tree, name);
	if (!err)
		pr_debug("removed xattr %s from file %s\n", name, path);

	if (empty_xattr_tree(fxt->tree)) {
		remove_file_xattr_tree(fxt);
		pr_debug("destroyed xattr tree for %s\n", fxt->path);
		destroy_file_xattr_tree(fxt);
	}

unlock:
	if (pthread_mutex_unlock(&files_tree_lock))
		pr_err("%s: failed to unlock xattr tree: %d\n", __func__, err);
	return err;

}

ssize_t spfs_getxattr(const char *path, const char *name,
		      void *value, size_t size)
{
	ssize_t err;
	struct file_xattr_tree_s *fxt;

	err = pthread_mutex_lock(&files_tree_lock);
	if (err) {
		pr_err("%s: failed to lock xattr tree: %d\n", __func__, err);
		return -err;
	}

	fxt = find_file_xattr_tree(path);
	if (!fxt) {
		err = -ENODATA;
		goto unlock;
	}

	err = tree_getxattr(fxt->tree, name, value, size);
	if (err >= 0)
		pr_debug("return xattr %s of file %s\n", name, path);

unlock:
	if (pthread_mutex_unlock(&files_tree_lock))
		pr_err("%s: failed to unlock xattr tree: %d\n", __func__, err);
	return err;
}

ssize_t spfs_listxattr(const char *path, char *list, size_t size)
{
	int err;
	struct file_xattr_tree_s *fxt;

	err = pthread_mutex_lock(&files_tree_lock);
	if (err) {
		pr_err("%s: failed to lock xattr tree: %d\n", __func__, err);
		return -err;
	}

	fxt = find_file_xattr_tree(path);
	if (!fxt) {
		err = -ENODATA;
		goto unlock;
	}

	err = tree_listxattr(fxt->tree, list, size);

unlock:
	if (pthread_mutex_unlock(&files_tree_lock))
		pr_err("%s: failed to unlock xattr tree: %d\n", __func__, err);
	return err;
}

int spfs_del_xattrs(const char *path)
{
	ssize_t err;
	struct file_xattr_tree_s *fxt;

	err = pthread_mutex_lock(&files_tree_lock);
	if (err) {
		pr_err("%s: failed to lock xattr tree: %d\n", __func__, err);
		return -err;
	}

	fxt = find_file_xattr_tree(path);
	if (fxt)
		remove_file_xattr_tree(fxt);

	if (pthread_mutex_unlock(&files_tree_lock))
		pr_err("%s: failed to unlock xattr tree: %d\n", __func__, err);

	if (!fxt)
		return -ENODATA;

	destroy_file_xattr_tree(fxt);
	return 0;
}

bool is_spfs_xattr(const char *xattr)
{
	char *f, *s;

	f = strchr(xattr, '.');
	if (!f)
		return false;

	s = strchr(f + 1, '.');
	if (!s)
		return false;

	return !strncmp(f + 1, "spfs", s - f - 1);
}

int spfs_move_xattrs(const char *from, const char *to)
{
	struct file_xattr_tree_s *from_fxt, *to_fxt;
	ssize_t err = 0;

	err = pthread_mutex_lock(&files_tree_lock);
	if (err) {
		pr_err("%s: failed to lock xattr tree: %d\n", __func__, err);
		return -err;
	}

	to_fxt = find_file_xattr_tree(to);
	if (to_fxt)
		destroy_file_xattr_tree(to_fxt);

	from_fxt = find_file_xattr_tree(from);
	if (from_fxt) {
		char *old_path = from_fxt->path;

		from_fxt->path = strdup(to);
		if (!from_fxt->path) {
			err = -ENOMEM;
			pr_err("failed to duplicate\n");
			goto unlock;
		}
		free(old_path);
		pr_debug("moved xattrs from %s to %s\n", from, to);
	}

unlock:
	if (pthread_mutex_unlock(&files_tree_lock))
		pr_err("%s: failed to unlock xattr tree: %d\n", __func__, err);

	return err;
}

int spfs_dup_xattrs(const char *from, const char *to)
{
	struct file_xattr_tree_s *from_fxt, *to_fxt;
	ssize_t err = 0;

	err = pthread_mutex_lock(&files_tree_lock);
	if (err) {
		pr_err("%s: failed to lock xattr tree: %d\n", __func__, err);
		return -err;
	}

	to_fxt = search_file_xattr_tree(to);
	from_fxt = find_file_xattr_tree(from);

	if (from_fxt) {
		put_xattr_tree(to_fxt->tree);
		to_fxt->tree = get_xattr_tree(from_fxt->tree);
	} else {
		remove_file_xattr_tree(to_fxt);
		destroy_file_xattr_tree(to_fxt);
	}

	if (pthread_mutex_unlock(&files_tree_lock))
		pr_err("%s: failed to unlock xattr tree: %d\n", __func__, err);

	pr_debug("duplicated xattrs from %s to %s\n", from, to);
	return err;
}
