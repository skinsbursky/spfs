#include <search.h>
#include <stdlib.h>
#include <limits.h>
#include <libgen.h>

#include "include/log.h"
#include "include/util.h"

#include "link_remap.h"
#include "processes.h"
#include "spfs.h"

struct link_remap_s {
	char		*path;
	unsigned	users;
};

static void *link_remap_tree_root = NULL;

static int compare_link_remap(const void *a, const void *b)
{
	const struct link_remap_s *f = a, *s = b;

	return strcmp(f->path, s->path);
}

static int collect_link_remap(const char *path, struct link_remap_s **lr)
{
	struct link_remap_s *new_lr, **found_lr;
	int err = -ENOMEM;

	new_lr = malloc(sizeof(*new_lr));
	if (!new_lr)
		return -ENOMEM;

	new_lr->path = strdup(path);
	if (!new_lr->path)
		goto free_new_lr;

	new_lr->users = 0;

	found_lr = tsearch(new_lr, &link_remap_tree_root, compare_link_remap);
	if (!found_lr) {
		pr_err("failed to add new map fd object to the tree\n");
		goto free_new_lr_path;
	}

	*lr = *found_lr;
	err = 0;

	if (*found_lr == new_lr)
		return 0;

free_new_lr_path:
	free(new_lr->path);
free_new_lr:
	free(new_lr);
	return err;
}

void put_link_remap(struct link_remap_s *link_remap)
{
	if (--link_remap->users) {
		pr_debug("%s: %s: %d\n", __func__, link_remap->path, link_remap->users);
		return;
	}

	pr_debug("unlinking %s\n", link_remap->path);
	if (unlink(link_remap->path))
		pr_perror("failed to unlink link_remap %s", link_remap->path);
}

static int get_link_remap(const char *path, struct link_remap_s **link_remap)
{
	struct link_remap_s *lr;
	int err;

	err = collect_link_remap(path, &lr);
	if (err)
		return err;

	lr->users++;
	*link_remap = lr;
	return 0;
}

static void free_link_remap_node(void *nodep)
{
	struct link_remap_s *lr = nodep;

	free(lr->path);
	free(lr);
}

void destroy_link_remap_tree(void)
{
	tdestroy(link_remap_tree_root, free_link_remap_node);
}

static int rename_link_to_path(const char *path, const char *link_remap)
{
	int err;

	err = link(link_remap, path);
	if (err) {
		pr_perror("failed to rename %s to %s", link_remap, path);
		return -errno;
	}
	pr_debug("        (%s ---> %s)\n", link_remap, path);
	return 0;
}

static char *generate_path_from_remap(const char *path, const char *link_remap)
{
	char *bname, *new;

	bname = strdup(link_remap);
	if (!bname) {
		pr_err("failed to duplicate string\n");
		return NULL;
	}

	new = xsprintf("%s_%s", path, basename(bname));

	free(bname);
	return new;
}

static int are_hardlinks(const char *path1, const char *path2)
{
	struct stat st1, st2;

	if (lstat(path1, &st1)) {
		pr_perror("failed to stat %s", path1);
		return -errno;
	}

	if (lstat(path2, &st2)) {
		pr_perror("failed to stat %s", path2);
		return -errno;
	}

	return !memcmp(&st1, &st2, sizeof(st1));
}

int handle_sillyrenamed(const char *path, const struct replace_info_s *ri,
			struct link_remap_s **link_remap,
			char **renamed_path)
{
	char remap[PATH_MAX];
	const char *real_path;
	int err;

	err = spfs_link_remap(ri->src_mnt_ref,
			      path + strlen(ri->target_mnt) + 1,
			      remap, PATH_MAX);
	if (err) {
		if (err == -ENODATA)
			err = 0;
		return err;
	}

	err = fixup_source_path(remap, PATH_MAX,
				ri->source_mnt, ri->target_mnt);
	if (err)
		return err;

	real_path = path;

	if (!access(path, F_OK)) {
		int ret;

		ret = are_hardlinks(path, remap);
		if (ret < 0)
			return ret;

		pr_warn("        (%s exists - %s)\n", path, ret ? "hardlink" : "other");

		real_path = *renamed_path = generate_path_from_remap(path, remap);
		if (!real_path)
			return -ENOMEM;
	}

	err = rename_link_to_path(real_path, remap);
	if (err)
		return err;

	err = get_link_remap(remap, link_remap);
	if (err) {
		pr_err("failed to get link_remap %s\n", remap);
		goto unlink_path;
	}

	return 0;

unlink_path:
	if (unlink(real_path))
		pr_perror("failed to unlink %s", path);
	return err;
}
