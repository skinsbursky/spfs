#include <stdlib.h>
#include <poll.h>
#include <signal.h>

#include <sys/mount.h>

#include "include/socket.h"
#include "include/log.h"
#include "include/util.h"
#include "include/ipc.h"

#include "context.h"
#include "spfs.h"
#include "freeze.h"
#include "replace.h"

/*
 * 1) Mount of SPFS
 *
 * mount;id=<spfs_id>;ns_pid=<pid>;ns_list=<list, separated by comma>;root=<root path>;mode=<proxy|stub>;proxy_dir=<proxy directory if proxy mode>;mountpoint=<path>
 *
 * Example:
 *
 * mount;id=87;ns_pid=17345;ns_list=user,net,mnt;root=/vz/root/102;mode=proxy;proxy_dir=/.criu-spfs-87/mnt
 *
 * 2) Change SPFS work mode:
 *
 * mode;id=<spfs_id>;mode=<proxy|stub>;proxy_dir=<proxy directory if proxy mode>
 *
 * 3) Replace SPFS with another file system:
 *
 * replace:id=<spfs_id>;source=<source>;type=<fs_type>;flags=<mount flags>;freeze_cgroup=<path to cgroup>
 *
 * 4) Switch processes from one fs to another
 *
 * switch:source=<path-to_source_mnt>;target=<path_to_target_mnt>;device=<src_mnt_dev_id>;freeze_cgroup=<path to cgroup>;ns_pid=<pid>
 *
 * After string comes options as blob (string or binary).
 */

typedef int (*cmd_handler_t)(int sock, struct spfs_manager_context_s *ctx, char *package, size_t size);

struct spfs_manager_cmd_handler_s {
	char *cmd;
	cmd_handler_t handle;
	bool fork;
};

struct opt_array_s {
	char *name;
	char *value;
	bool no_value;
};

static int parse_cmd_options(struct opt_array_s *array, char *options)
{
	struct opt_array_s *o;
	char *opt;

	while ((opt = strsep(&options, ";")) != NULL) {
		bool found = false;

		o = array;
		while (o->name) {
			if (!strncmp(opt, o->name, strlen(o->name))) {
				found = true;

				if (o->no_value) {
					o->value = (void *)1;
					break;
				}

				if (o->value) {
					pr_err("duplicated %s option\n", o->name);
					return -EINVAL;
				}
				o->value = opt + strlen(o->name);
				if (strlen(o->value) == 0) {
					pr_err("option %s is empty\n", o->name);
					return -EINVAL;
				}
				break;
			}
			o++;
		}
		if (!found && strlen(opt)) {
			pr_err("unsupported option: %s\n", opt);
			return -EINVAL;
		}
	}
	return 0;
}

static int mount_spfs(struct spfs_manager_context_s *ctx,
		      struct spfs_info_s *info,
		      const char *mode, const char *proxy_dir)
{
	int status = -ENOMEM, initpipe[2], timeout_ms = 500000;
	struct pollfd pfd;
	pid_t pid;

	if (pipe(initpipe)) {
		pr_err("failed to create pipe\n");
		return -errno;
	}

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			status = -errno;
			goto close_pipe;
		case 0:
			close(initpipe[0]);
			_exit(do_mount_spfs(info, mode, proxy_dir, initpipe[1]));
	}

	/* First, close write end of the pipe */
	close(initpipe[1]);
	initpipe[1] = -1;

	/* Now wait till "ready fd" is closed */
	pfd.fd = initpipe[0];
	pfd.events = POLLERR | POLLHUP;
	pfd.revents = 0;

repeat:
	switch (poll(&pfd, 1, timeout_ms)) {
		case -1:
			if (errno == EINTR)
				goto repeat;

			pr_perror("poll failed");
			status = -errno;
			goto kill_spfs;
		case 0:
			pr_err("Child wasn't ready for %d ms.\n"
			       "Something bad happened\n", timeout_ms);
			status = -ETIMEDOUT;
			goto kill_spfs;
	}

	status = -EPERM;

	if (pfd.revents & POLLERR) {
		pr_err("poll return POLERR\n");
		goto kill_spfs;
	}

	/* And check, that process is still alive */
	if (collect_child(pid, &status, WNOHANG) != ECHILD) {
		pr_err("%d exited unexpectedly\n", pid);
		goto umount_spfs;
	}

	status = 0;
	pr_info("%s: spfs on %s with pid %d started successfully\n", __func__,
			info->mnt.mountpoint, pid);

	info->pid = pid;

close_pipe:
	if (initpipe[1] >= 0)
		close(initpipe[1]);
	close(initpipe[0]);
	return status;

kill_spfs:
	kill_child_and_collect(pid);
umount_spfs:
	umount_spfs(info);
	goto close_pipe;
}

static int process_mount_cmd(int sock, struct spfs_manager_context_s *ctx,
			     char *options, size_t size)
{
	struct opt_array_s opt_array[] = {
		[0] = { "id=", NULL },
		[1] = { "ns_pid=", NULL },	// optional
		[2] = { "root=", NULL },	// optional
		[3] = { "mode=", NULL },
		[4] = { "proxy_dir=", NULL },	// optional
		[5] = { "mountpoint=", NULL },
		{ NULL, NULL },
	};
	const char *opt_id, *opt_ns_pid, *opt_root;
	const char *opt_mode, *opt_proxy_dir, *opt_mountpoint;
	struct spfs_info_s *info;
	int err;
	long ns_pid = -1;

	err = parse_cmd_options(opt_array, options);
	if (err) {
		pr_err("failed to parse options for mount command\n");
		return -EINVAL;
	}

	opt_id = opt_array[0].value;
	opt_ns_pid = opt_array[1].value;
	opt_root = opt_array[2].value;
	opt_mode = opt_array[3].value;
	opt_proxy_dir = opt_array[4].value;
	opt_mountpoint = opt_array[5].value;

	if (opt_id == NULL) {
		pr_err("mount id wasn't provided\n");
		return -EINVAL;
	}

	if (opt_mode == NULL) {
		pr_err("mode wasn't provided\n");
		return -EINVAL;
	}

	if (!strcmp(opt_mode, "proxy") && (opt_proxy_dir == NULL)) {
		pr_err("no proxy directory was provided\n");
		return -EINVAL;
	}

	if (opt_mountpoint == NULL) {
		pr_err("mountpoint wasn't provided\n");
		return -EINVAL;
	}

	if (opt_ns_pid) {
		err = xatol(opt_ns_pid, &ns_pid);
		if (err) {
			pr_err("failed to convert pid: %s\n", opt_ns_pid);
			return err;
		}
	}

	err = create_spfs_info(opt_id, opt_mountpoint, ns_pid, opt_root,
			       ctx->ns_fds, ctx->ovz_id, &info);
	if (err)
		return err;

	err = mount_spfs(ctx, info, opt_mode, opt_proxy_dir);
	if (err) {
		pr_err("failed to mount spfs to %s\n", opt_mountpoint);
		return err;
	}

	err = update_spfs_info(info);
	if (err)
		goto umount_spfs;

	err = add_spfs_info(ctx->spfs_mounts, info);
	if (err)
		goto release_spfs;

	return 0;

release_spfs:
	release_spfs_info(info);
umount_spfs:
	umount_spfs(info);
	return err;
}

static int change_spfs_mode(struct spfs_manager_context_s *ctx,
			    const struct spfs_info_s *info,
			    spfs_mode_t mode, const char *proxy_dir)
{
	int err;
	struct mount_info_s *mnt;

	if (info)
		return spfs_send_mode(info, mode, proxy_dir);

	err = lock_shared_list(ctx->spfs_mounts);
	if (err)
		return err;

	list_for_each_entry(mnt, &ctx->spfs_mounts->list, list) {
		info = container_of(mnt, const struct spfs_info_s, mnt);

		err = spfs_send_mode(info, mode, proxy_dir);
		if (err)
			break;
	}

	unlock_shared_list(ctx->spfs_mounts);

	return err;
}

static int process_mode_cmd(int sock, struct spfs_manager_context_s *ctx,
			    char *options, size_t size)
{
	struct opt_array_s opt_array[] = {
		[0] = { "id=", NULL },
		[1] = { "mode=", NULL },
		[2] = { "proxy_dir=", NULL },
		[3] = { "all", NULL, true },
		{ NULL, NULL },
	};
	const char *opt_id, *opt_mode, *opt_proxy_dir, *opt_all;
	const struct spfs_info_s *info = NULL;
	spfs_mode_t mode;
	int err;

	err = parse_cmd_options(opt_array, options);
	if (err) {
		pr_err("failed to parse options for mode command\n");
		return -EINVAL;
	}

	opt_id = opt_array[0].value;
	opt_mode = opt_array[1].value;
	opt_proxy_dir = opt_array[2].value;
	opt_all = opt_array[3].value;

	if (!opt_id && !opt_all) {
		pr_err("mount id wasn't provided\n");
		return -EINVAL;
	}

	if (!opt_mode) {
		pr_err("mode wasn't provided\n");
		return -EINVAL;
	}

	if (!strcmp(opt_mode, "proxy") && !opt_proxy_dir) {
		pr_err("no proxy directory was provided\n");
		return -EINVAL;
	}

	if (opt_id) {
		info = find_spfs_by_id(ctx->spfs_mounts, opt_array[0].value);
		if (!info) {
			pr_err("failed to find spfs info with id %s\n", opt_array[0].value);
			return -EINVAL;
		}
	}

	mode = spfs_mode(opt_mode, opt_proxy_dir);
	if (mode < 0)
		return mode;

	return change_spfs_mode(ctx, info, mode, opt_proxy_dir);
}

static int process_replace_mode_all(int sock, struct spfs_manager_context_s *ctx,
				    unsigned mode)
{
	int err;
	struct mount_info_s *mnt;
	struct spfs_info_s *info;

	err = lock_shared_list(ctx->spfs_mounts);
	if (err)
		return err;

	list_for_each_entry(mnt, &ctx->spfs_mounts->list, list) {
		info = container_of(mnt, struct spfs_info_s, mnt);

		err = spfs_apply_replace_mode(info, mode);
		if (err)
			break;
	}

	unlock_shared_list(ctx->spfs_mounts);

	return err;
}

static int get_replace_mode(const char *mode)
{
	if (!strcmp(mode, "hold"))
		return SPFS_REPLACE_MODE_HOLD;
	else if (!strcmp(mode, "release"))
		return SPFS_REPLACE_MODE_RELEASE;
	return -EINVAL;
}

static int process_replace_cmd(int sock, struct spfs_manager_context_s *ctx,
			       char *options, size_t size)
{
	struct opt_array_s opt_array[] = {
		[0] = { "id=", NULL },
		[1] = { "source=", NULL },
		[2] = { "type=", NULL },
		[3] = { "flags=", NULL },
		[4] = { "freeze_cgroup=", NULL },
		[5] = { "bindmounts=", NULL },
		[6] = { "mode=", NULL },
		[7] = { "all", NULL, true },
		{ NULL, NULL },
	};
	const char *opt_id, *opt_source, *opt_type, *opt_flags;
	const char *opt_freeze_cgroup, *opt_bindmounts, *opt_mode, *opt_all;
	struct spfs_info_s *info;
	void *opts = NULL;
	int err;
	spfs_replace_mode_t mode = SPFS_REPLACE_MODE_HOLD;

	if (size > strlen(options) + 1)
		opts = options + strlen(options) + 1;

	err = parse_cmd_options(opt_array, options);
	if (err) {
		pr_err("failed to parse options for replace command\n");
		return -EINVAL;
	}

	opt_id = opt_array[0].value;
	opt_source = opt_array[1].value;
	opt_type = opt_array[2].value;
	opt_flags = opt_array[3].value;
	opt_freeze_cgroup = opt_array[4].value;
	opt_bindmounts = opt_array[5].value;
	opt_mode = opt_array[6].value;
	opt_all = opt_array[7].value;

	if (opt_mode) {
		mode = get_replace_mode(opt_mode);
		if (mode < 0) {
			pr_err("mode is invalid: %s\n", opt_mode);
			return -EINVAL;
		}
	}

	if (opt_all)
		return process_replace_mode_all(sock, ctx, mode);

	if (opt_id == NULL) {
		pr_err("mount id wasn't provided\n");
		return -EINVAL;
	}

	if (opt_source == NULL) {
		pr_err("source wasn't provided\n");
		return -EINVAL;
	}

	if (opt_type == NULL) {
		pr_err("type wasn't provided\n");
		return -EINVAL;
	}

	if (opt_flags == NULL) {
		pr_err("flags weren't provided\n");
		return -EINVAL;
	}

	info = find_spfs_by_id(ctx->spfs_mounts, opt_id);
	if (!info) {
		pr_err("failed to find spfs info with id %s\n", opt_id);
		return -EINVAL;
	}

	if (opt_freeze_cgroup) {
		err = lock_shared_list(ctx->spfs_mounts);
		if (err)
			return err;

		if (info->fg) {
			pr_err("failed to set freezer cgroup %s for info %s\n",
					opt_freeze_cgroup, info->mnt.id);
			err = -EEXIST;
		} else {
			info->fg = get_freeze_cgroup(ctx->freeze_cgroups, opt_freeze_cgroup);
			if (!info->fg)
				pr_err("failed to get freezer cgroup %s for info %s\n",
						opt_freeze_cgroup, info->mnt.id);
		}

		(void) unlock_shared_list(ctx->spfs_mounts);

		if (err)
			return err;
	}

	if (opt_bindmounts) {
		err = spfs_add_mount_paths(info, opt_bindmounts);
		if (err)
			return err;
	}

	err = spfs_apply_replace_mode(info, mode);
	if (err)
		return err;

	/* TODO: there can be races in spfs replacement. Is it a problem? */
	info->replacer = getpid();

	return replace_spfs(sock, info, opt_source, opt_type, opt_flags, opts);
}

static int process_switch_cmd(int sock, struct spfs_manager_context_s *ctx,
			      char *options, size_t size)
{
	struct opt_array_s opt_array[] = {
		[0] = { "source=", NULL },
		[1] = { "target=", NULL },
		[2] = { "freeze_cgroup=", NULL },
		[3] = { "device=", NULL },
		[4] = { "ns_pid=", NULL },
		{ NULL, NULL },
	};
	int err;
	struct freeze_cgroup_s *fg;
	long ns_pid = 0, src_dev = 0;
	char *source_mnt, *target_mnt;
	char *freeze_cgroup, *device, *ns_process_id;

	err = parse_cmd_options(opt_array, options);
	if (err) {
		pr_err("failed to parse options for replace command\n");
		return -EINVAL;
	}

	source_mnt = opt_array[0].value;
	target_mnt = opt_array[1].value;
	freeze_cgroup = opt_array[2].value;
	device = opt_array[3].value;
	ns_process_id = opt_array[4].value;

	if (target_mnt == NULL) {
		pr_err("target mountpoint wasn't provided\n");
		return -EINVAL;
	}

	if (freeze_cgroup == NULL) {
		pr_err("freezer cgroup wasn't provided\n");
		return -EINVAL;
	}

	if ((source_mnt && device) ||
	    (!source_mnt && !device)) {
		pr_err("either source mountpoint or source device must be specified\n");
		return -EINVAL;
	}

	if (device) {
		err = xatol(device, &src_dev);
		if (err) {
			pr_err("failed to convert device id: %s\n", device);
			return err;
		}
	}

	if (ns_process_id) {
		err = xatol(ns_process_id, &ns_pid);
		if (err) {
			pr_err("failed to convert pid: %s\n", ns_process_id);
			return err;
		}
	}

	fg = get_freeze_cgroup(ctx->freeze_cgroups, freeze_cgroup);
	if (!fg) {
		pr_err("failed to get freezer cgroup %s\n", freeze_cgroup);
		return -EINVAL;
	}

	target_mnt = canonicalize_file_name(target_mnt);
	if (!target_mnt) {
		pr_perror("failed to get %s canonical view", opt_array[1].value);
		return -errno;
	}

	if (source_mnt) {
		struct stat st;

		source_mnt = canonicalize_file_name(source_mnt);
		if (!source_mnt) {
			pr_perror("failed to get %s canonical view", opt_array[0].value);
			err = -errno;
			goto free_target_mnt;
		}

		if (stat(source_mnt, &st) < 0) {
			pr_perror("failed to stat %s", source_mnt);
			err = -errno;
			goto free_target_mnt;
		}
		src_dev = st.st_dev;
	}

	err = replace_resources(fg, source_mnt, src_dev, target_mnt, ns_pid);

	free(source_mnt);
free_target_mnt:
	free(target_mnt);
	return err;
}

const struct spfs_manager_cmd_handler_s handlers[] = {
	{ "mount", process_mount_cmd, false },
	{ "mode", process_mode_cmd, true },
	{ "replace", process_replace_cmd, true },
	{ "switch", process_switch_cmd, true },
	{ NULL, NULL }
};

static int split_request(char *package, char **command, char **options)
{
	char *semicolon;

	semicolon = strchr(package, ';');
	if (!semicolon) {
		pr_err("failed to find command word\n");
		return -EINVAL;
	}
	*semicolon = '\0';

	*command = package;
	*options = semicolon + 1;
	return 0;
}

const struct spfs_manager_cmd_handler_s *get_cmd_handler(const char *cmd)
{
	const struct spfs_manager_cmd_handler_s *ptr = handlers;

	while(ptr->cmd) {
		if (!strcmp(ptr->cmd, cmd))
			return ptr;
		ptr++;
	}
	return NULL;
}

static int spfs_manager_handle_packet(cmd_handler_t handler, int sock, void *data, void *package, size_t psize)
{
	int ret;

	ret = handler(sock, data, package, psize);
	(void) send_status(sock, ret);
	return ret;
}

int spfs_manager_packet_handler(int sock, void *data, void *package, size_t psize)
{
	int err;
	char *cmd, *options;
	const struct spfs_manager_cmd_handler_s *handler;

	err = split_request(package, &cmd, &options);
	if (err)
		return err;

	pr_debug("received request: \"%s\"\n", cmd);
	pr_debug("    options: %s\n", options);

	handler = get_cmd_handler(cmd);
	if (!handler)
		return -EINVAL;

	if (handler->fork) {
		switch (fork()) {
			case -1:
				pr_perror("failed to fork");
				return -errno;
			case 0:

				/* TODO dropping inherited handlerforof the
				 * SIGCHLD might be done somehow better.
				 * This is required to prevent a situation,
				 * when wait() returns ECHILD
				 * (ct_run()->collect_child).
				 */
				signal(SIGCHLD, SIG_DFL);

				_exit(spfs_manager_handle_packet(handler->handle, sock, data, options, psize - (options - cmd)));
			default:
				return 0;
		}
	}

	return spfs_manager_handle_packet(handler->handle, sock, data, options, psize - (options - cmd));
}
