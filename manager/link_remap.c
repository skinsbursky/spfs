#include <search.h>
#include <stdlib.h>
#include "include/log.h"

#include "link_remap.h"

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
	link_remap->users--;
}

int get_link_remap(const char *path, struct link_remap_s **link_remap)
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

	if (lr->users == 0) {
		pr_debug("unlinking %s\n", lr->path);
		if (unlink(lr->path))
			pr_perror("failed to unlink link_remap %s", lr->path);
	}
	free(lr->path);
	free(lr);
}

void cleanup_link_remaps(void)
{
	tdestroy(link_remap_tree_root, free_link_remap_node);
}
