#include "spfs_config.h"

#include <stdlib.h>
#include <poll.h>

#include <sys/mount.h>

#include "include/socket.h"

#include "include/log.h"
#include "include/util.h"
#include "include/shm.h"
#include "include/ipc.h"

#include "spfs/interface.h"

#include "context.h"
#include "interface.h"
#include "mount.h"
#include "spfs.h"
#include "freeze.h"

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

static int exec_spfs(int pipe, const struct spfs_info_s *info, char *mode,
		     char *proxy_dir, char *socket_path, char *log_path,
		     char *mountpoint)
{
	const char *spfs = FS_NAME;
	char wpipe[16];
	char **options;
	int err = -ENOMEM;

	sprintf(wpipe, "%d", pipe);

	options = exec_options(0, "spfs", "-vvvv", "-f", "--single-user",
				"--mode", mode,
				"--socket-path", socket_path,
				"--ready-fd", wpipe,
				"--log", log_path,
				mountpoint, NULL);
	if (options && strlen(info->root))
		options = add_exec_options(options, "--root", info->root, NULL);
	if (options && proxy_dir)
		options = add_exec_options(options, "--proxy-dir", proxy_dir, NULL);

	if (!options)
		return -ENOMEM;

	if (info->ns_pid)
		if (join_namespaces(info->ns_pid, info->ns_list))
			goto free_options;

	err = execvp_print(spfs, options);

free_options:
	free(options);
	return err;
}

static int mount_spfs(struct spfs_manager_context_s *ctx,
		      struct spfs_info_s *info, char *mode,
		      char *proxy_dir)
{
	char *cwd, *socket_path, *log_path, *mountpoint;
	int status = -ENOMEM, initpipe[2], timeout_ms = 5000;
	struct pollfd pfd;
	pid_t pid;

	if (pipe(initpipe)) {
		pr_err("failed to create pipe\n");
		return -errno;
	}

	cwd = get_current_dir_name();
	if (!cwd) {
		pr_perror("failed to get cwd");
		goto close_pipe;
	}

	mountpoint = xsprintf("%s%s", info->root, info->mountpoint);
	if (!mountpoint)
		goto free_cwd;

	socket_path = xsprintf("%s/%s", cwd, info->socket_path);
	if (!socket_path)
		goto free_mountpoint;

	log_path = xsprintf("%s/spfs-%s.log", cwd, info->id);
	if (!log_path)
		goto free_socket_path;

	status = create_dir("%s%s", info->root, proxy_dir);
	if (status)
		goto free_log_path;

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			status = -errno;
			goto free_log_path;
		case 0:
			close(initpipe[0]);
			_exit(exec_spfs(initpipe[1], info, mode,
					proxy_dir, socket_path, log_path,
					mountpoint));
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

	info->sock = seqpacket_sock(info->socket_path, true, false, NULL);
	if (info->sock < 0) {
		pr_err("failed to connect to spfs with id %s\n", info->id);
		goto umount_spfs;
	}

	status = 0;
	pr_info("%s: spfs on %s started successfully\n", __func__,
			info->mountpoint);

	info->pid = pid;

free_log_path:
	free(log_path);
free_socket_path:
	free(socket_path);
free_mountpoint:
	free(mountpoint);
free_cwd:
	free(cwd);
close_pipe:
	if (initpipe[1] >= 0)
		close(initpipe[1]);
	close(initpipe[0]);
	return status;

kill_spfs:
	kill_child_and_collect(pid);
umount_spfs:
	umount(info->mountpoint);
	goto free_log_path;
}

static int process_mount_cmd(int sock, struct spfs_manager_context_s *ctx,
			     char *options, size_t size)
{
	struct opt_array_s opt_array[] = {
		[0] = { "id=", NULL },
		[1] = { "ns_pid=", NULL },	// optional
		[2] = { "ns_list=", NULL },	// optional
		[3] = { "root=", NULL },	// optional
		[4] = { "mode=", NULL },
		[5] = { "proxy_dir=", NULL },	// optional
		[6] = { "mountpoint=", NULL },
		{ NULL, NULL },
	};
	struct spfs_info_s *info;
	int err;

	err = parse_cmd_options(opt_array, options);
	if (err) {
		pr_err("failed to parse options for mount command\n");
		return -EINVAL;
	}

	if (opt_array[0].value == NULL) {
		pr_err("mount id wasn't provided\n");
		return -EINVAL;
	}

	if (opt_array[1].value && (opt_array[2].value == NULL)){
		pr_err("namespases pid was provided without namespaces list\n");
		return -EINVAL;
	}

	if (opt_array[2].value && (opt_array[1].value == NULL)){
		pr_err("namespases list was provided without namespaces pid\n");
		return -EINVAL;
	}

	if (opt_array[4].value == NULL) {
		pr_err("mode wasn't provided\n");
		return -EINVAL;
	}

	if (!strcmp(opt_array[4].value, "proxy") && (opt_array[5].value == NULL)) {
		pr_err("no proxy directory was provided\n");
		return -EINVAL;
	}

	if (opt_array[6].value == NULL) {
		pr_err("mountpoint wasn't provided\n");
		return -EINVAL;
	}

	err = -ENOMEM;

	info = shm_alloc(sizeof(*info));
	if (!info) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	info->id = shm_xsprintf(opt_array[0].value);
	if (!info->id) {
		pr_perror("failed to allocate string\n");
		return -ENOMEM;
	}

	if (opt_array[1].value) {
		err = xatol(opt_array[1].value, &info->ns_pid);
		if (err) {
			pr_err("failed to convert pid: %s\n", opt_array[1].value);
			return err;
		}

		info->ns_list = shm_xsprintf(opt_array[2].value);
		if (!info->ns_list) {
			pr_perror("failed to allocate string\n");
			return -ENOMEM;
		}
	}

	if (opt_array[3].value) {
		info->root = shm_xsprintf(opt_array[3].value);
		if (!info->root) {
			pr_perror("failed to allocate string\n");
			return -ENOMEM;
		}

		if (stat(info->root, &info->root_stat)) {
			pr_perror("failed to stat %s", info->root);
			return -errno;
		}
	} else {
		info->root = shm_alloc(1);
		if (!info->root) {
			pr_perror("failed to allocate string\n");
			return -ENOMEM;
		}
		info->root[0] = '\0';
	}

	info->mountpoint = shm_xsprintf(opt_array[6].value);
	if (!info->mountpoint) {
		pr_perror("failed to allocate string\n");
		return -ENOMEM;
	}

	info->work_dir = shm_xsprintf("/run/spfs/%s", info->id);
	if (!info->work_dir) {
		pr_perror("failed to allocate string\n");
		return -ENOMEM;
	}

	err = create_dir("%s%s", info->root, info->work_dir);
	if (err)
		return err;

	info->socket_path = shm_xsprintf("spfs-%s.sock", info->id);
	if (!info->socket_path) {
		pr_perror("failed to allocate string\n");
		return -ENOMEM;
	}

	err = init_shared_list(&info->mountpaths);
	if (err)
		return err;

	err = spfs_add_mount_paths(info, info->mountpoint);
	if (err)
		return err;

	INIT_LIST_HEAD(&info->list);

	/* TODO: should we add mounpoint _after_ mount? */
	err = add_spfs_info(ctx->spfs_mounts, info);
	if (err)
		return -ENOMEM;

	err = mount_spfs(ctx, info, opt_array[4].value, opt_array[5].value);
	if (err)
		goto del_spfs_info;

	return 0;

del_spfs_info:
	del_spfs_info(ctx->spfs_mounts, info);
	return err;
}

static int change_spfs_mode(struct spfs_manager_context_s *ctx,
			    const struct spfs_info_s *info,
			    spfs_mode_t mode, const char *proxy_dir)
{
	int err;

	if (info)
		return spfs_send_mode(info, mode, proxy_dir);

	err = lock_shared_list(ctx->spfs_mounts);
	if (err)
		return err;

	list_for_each_entry(info, &ctx->spfs_mounts->list, list) {
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
	const struct spfs_info_s *info = NULL;
	spfs_mode_t mode;
	int err;

	err = parse_cmd_options(opt_array, options);
	if (err) {
		pr_err("failed to parse options for mode command\n");
		return -EINVAL;
	}

	if ((opt_array[0].value == NULL) && (opt_array[3].value == NULL)) {
		pr_err("mount id wasn't provided\n");
		return -EINVAL;
	}

	if (opt_array[1].value == NULL) {
		pr_err("mode wasn't provided\n");
		return -EINVAL;
	}

	if (!strcmp(opt_array[1].value, "proxy") && (opt_array[2].value == NULL)) {
		pr_err("no proxy directory was provided\n");
		return -EINVAL;
	}

	if (opt_array[0].value) {
		info = find_spfs_by_id(ctx->spfs_mounts, opt_array[0].value);
		if (!info) {
			pr_err("failed to find spfs info with id %s\n", opt_array[0].value);
			return -EINVAL;
		}
	}

	mode = spfs_mode(opt_array[1].value, opt_array[2].value);
	if (mode < 0)
		return mode;

	return change_spfs_mode(ctx, info, mode, opt_array[2].value);
}

int set_freeze_cgroup(struct spfs_manager_context_s *ctx, struct spfs_info_s *info, const char *path)
{
	int err;
	struct shared_list *list = ctx->freeze_cgroups;
	struct freeze_cgroup_s *fg;

	err = lock_shared_list(list);
	if (err)
		return err;

	fg = __find_freeze_cgroup(list, path);
	if (!fg) {
		fg = create_freeze_cgroup(path);
		if (fg) {
			list_add_tail(&fg->list, &ctx->freeze_cgroups->list);
			info->fg = fg;
		} else
			err = -ENOMEM;
	}
	if (fg)
		info->fg = fg;

	(void) unlock_shared_list(list);
	return err;
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
		{ NULL, NULL },
	};
	struct spfs_info_s *info;
	void *opts = NULL;
	int err;

	if (size > strlen(options) + 1)
		opts = options + strlen(options) + 1;

	err = parse_cmd_options(opt_array, options);
	if (err) {
		pr_err("failed to parse options for replace command\n");
		return -EINVAL;
	}

	if (opt_array[0].value == NULL) {
		pr_err("mount id wasn't provided\n");
		return -EINVAL;
	}

	if (opt_array[1].value == NULL) {
		pr_err("source wasn't provided\n");
		return -EINVAL;
	}

	if (opt_array[2].value == NULL) {
		pr_err("type wasn't provided\n");
		return -EINVAL;
	}

	if (opt_array[3].value == NULL) {
		pr_err("flags weren't provided\n");
		return -EINVAL;
	}

	info = find_spfs_by_id(ctx->spfs_mounts, opt_array[0].value);
	if (!info) {
		pr_err("failed to find spfs info with id %s\n", opt_array[0].value);
		return -EINVAL;
	}

	if (opt_array[4].value) {
		err = lock_shared_list(ctx->spfs_mounts);
		if (err)
			return err;

		if (info->fg) {
			pr_err("failed to set freezer cgroup %s for info %s\n",
					opt_array[4].value, info->id);
			err = -EEXIST;
		} else {
			err = set_freeze_cgroup(ctx, info, opt_array[4].value);
			if (err)
				pr_err("failed to set freezer cgroup %s for info %s\n",
						opt_array[4].value, info->id);
		}

		(void) unlock_shared_list(ctx->spfs_mounts);

		if (err)
			return err;
	}

	if (opt_array[5].value) {
		err = spfs_add_mount_paths(info, opt_array[5].value);
		if (err)
			return err;
	}

	return replace_mount(sock, info, opt_array[1].value, opt_array[2].value,
			     opt_array[3].value, opts);
}

const struct spfs_manager_cmd_handler_s handlers[] = {
	{ "mount", process_mount_cmd, false },
	{ "mode", process_mode_cmd, true },
	{ "replace", process_replace_cmd, true },
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
	return send_status(sock, handler(sock, data, package, psize));
}

int spfs_manager_packet_handler(int sock, void *data, void *package, size_t psize)
{
	int err;
	char *cmd, *options;
	const struct spfs_manager_cmd_handler_s *handler;

	err = split_request(package, &cmd, &options);
	if (err)
		return err;

	pr_debug("Received command request: '%s', options: '%s'\n", cmd, options);

	handler = get_cmd_handler(cmd);
	if (!handler)
		return -EINVAL;

	if (handler->fork) {
		switch (fork()) {
			case -1:
				pr_perror("failed to fork");
				return -errno;
			case 0:
				_exit(spfs_manager_handle_packet(handler->handle, sock, data, options, psize - (options - cmd)));
			default:
				return 0;
		}
	}

	return spfs_manager_handle_packet(handler->handle, sock, data, options, psize - (options - cmd));
}
