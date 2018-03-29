#include "spfs_config.h"

#include <fuse.h>
#include <getopt.h>
#include <stdlib.h>

#include <sys/capability.h>

#include "include/log.h"
#include "include/util.h"
#include "include/ipc.h"
#include "include/namespaces.h"

#include "context.h"

extern struct fuse_operations gateway_operations;

static void copy_args(char **old, int *old_index, char **new, int *new_index)
{
	while (*old_index < optind) {
		pr_debug("copy fuse option: %s\n", old[*old_index]);
		new[*new_index] = old[*old_index];
		*new_index += 1;
		*old_index += 1;
	}
}

static void help(int argc, char **argv, int help_level)
{
	char *mountpoint;
	int multithreaded;

	printf("usage: %s mountpoint [options]\n", argv[0]);
	printf("\n");
	printf("general options:\n");
	printf("\t-m   --mode                  work mode (\"stub\" or \"proxy\")\n");
	printf("\t-p   --proxy-dir             path for proxy mode\n");
	printf("\t     --proxy-mntns-pid       pid with mount namespace for proxy directory\n");
	printf("\t-r   --root                  directory to chroot to\n");
	printf("\t-l   --log                   log file\n");
	printf("\t-s   --socket-path           control socket bind path\n");
	printf("\t-h   --help                  print help (for double option will print fuse help)\n");
	printf("\t     --ready-fd              fd number to report ready status\n");
	printf("\t     --single-user           spfs won't close socket connection\n");
	printf("\t     --mntns-pid             pid with mount namespace for mountpoint\n");
	printf("\t-v                           increase verbosity (can be used multiple times)\n");
	printf("\n");

	if (help_level > 1) {
		pr_info("Calling fuse for '-h' option\n");
		fuse_setup(argc, argv,
			  &gateway_operations, sizeof(gateway_operations),
			  &mountpoint, &multithreaded, NULL);
	}
}

int parse_options(int *orig_argc, char ***orig_argv,
		  char **proxy_dir, spfs_mode_t *mode, char **log, char **socket_path,
		  int *verbosity, char **root, int *ready_fd, bool *single_user,
		  int *mnt_ns_pid, int *proxy_mnt_ns_pid)
{
	static struct option opts[] = {
		{"proxy-dir",	required_argument,	0, 'p'},
		{"mode",	required_argument,	0, 'm'},
		{"log",		required_argument,	0, 'l'},
		{"root",	required_argument,	0, 'r'},
		{"socket-path",	required_argument,	0, 's'},
		{"help",	no_argument,		0, 'h'},
		{"ready-fd",	required_argument,	0, 1000},
		{"single-user",	no_argument,		0, 1001},
		{"mntns-pid",	required_argument,	0, 1002},
		{"proxy-mntns-pid",	required_argument,	0, 1003},
		{0,		0,			0,  0 }
	};
	int oind = 0, nind = 1;
	int argc = *orig_argc, new_argc = 0, prev_optind = 0, help_level = 0;
	char **argv = *orig_argv, **new_argv;
	char *mode_str = "stub";
	char *ready_fd_str = NULL;
	char *mnt_ns_pid_str = NULL;
	char *proxy_mnt_ns_pid_str = NULL;

	new_argv = malloc(sizeof(char *) * (argc + 1));
	if (!new_argv) {
		pr_crit("failed to allocate new optons array\n");
		return -ENOMEM;
	}
	memset(new_argv, 0, sizeof(*new_argv));

	/* Copy program name */
	new_argv[0] = argv[0];
	new_argc++;

	/* Disable error messages from getopt */
	opterr = 0;

	while (1) {
		int c;

		c = getopt_long(argc, argv, "p:r:l:m:s:vh", opts, &oind);
		if (c == -1)
			break;

		if (!prev_optind) {
			/* First option */
			prev_optind++;
			if (optind != 1)
				/* Some non-option paramete was skipped.
				 * Need to copy it. */
				copy_args(argv, &nind, new_argv, &new_argc);
		}

		switch (c) {
			case 'p':
				*proxy_dir = optarg;
				nind += 2;
				break;
			case 'm':
				mode_str = optarg;
				nind += 2;
				break;
			case 'l':
				*log = optarg;
				nind += 2;
				break;
			case 's':
				*socket_path = optarg;
				nind += 2;
				break;
			case 'r':
				*root = optarg;
				nind += 2;
				break;
			case 'v':
				if (optind > prev_optind)
					nind += 1;
				*verbosity += 1;
				break;
			case 'h':
				if (help_level++)
					new_argv[new_argc++] = "-h";
				break;
			case 1000:
				ready_fd_str = optarg;
				nind += 2;
				break;
			case 1001:
				*single_user = true;
				nind += 1;
				break;
			case 1002:
				mnt_ns_pid_str = optarg;
				nind += 2;
				break;
			case 1003:
				proxy_mnt_ns_pid_str = optarg;
				nind += 2;
				break;
			case '?':
				copy_args(argv, &nind, new_argv, &new_argc);
				break;
			default:
				pr_warn("getopt returned character code: 0%o\n");
				break;
		}
		prev_optind = optind;
	}

	if (help_level) {
		help(new_argc, new_argv, help_level);
		exit(0);
	}

	*mode = spfs_mode(mode_str, *proxy_dir);
	if (*mode == SPFS_INVALID_MODE)
		goto inval_args;

	if (ready_fd_str) {
		if (xatoi(ready_fd_str, ready_fd) < 0) {
			pr_err("failed to convert --ready-fd\n");
			goto inval_args;
		}

		if (fcntl(*ready_fd, F_GETFD) == -1) {
			pr_err("fd %d is invalid\n", *ready_fd);
			goto inval_args;
		}
	}

	if (mnt_ns_pid_str) {
		char path[] = "/proc/XXXXXXXXXX/ns/mnt";

		if (xatoi(mnt_ns_pid_str, mnt_ns_pid) < 0) {
			pr_err("failed to convert --mntns-pid\n");
			goto inval_args;
		}

		sprintf(path,"/proc/%d/ns/mnt", *mnt_ns_pid);
		if (access(path, F_OK)) {
			pr_perror("failed to access %s", path);
			goto inval_args;
		}
	}

	if (proxy_mnt_ns_pid_str) {
		char path[] = "/proc/XXXXXXXXXX/ns/mnt";

		if (xatoi(proxy_mnt_ns_pid_str, proxy_mnt_ns_pid) < 0) {
			pr_err("failed to convert --proxy-mntns-pid\n");
			goto inval_args;
		}

		sprintf(path,"/proc/%d/ns/mnt", *proxy_mnt_ns_pid);
		if (access(path, F_OK)) {
			pr_perror("failed to access %s", path);
			goto inval_args;
		}
	}

	optind = *orig_argc;
	copy_args(argv, &nind, new_argv, &new_argc);

	*orig_argc = new_argc;
	*orig_argv = new_argv;

	/* Restore global optind variable for fuse options parsing */
	optind = 1;
	/* Enable error messages from getopt */
	opterr = 1;

	return 0;

inval_args:
	free(new_argv);
	return -EINVAL;
}

static struct fuse *setup_fuse(struct fuse_args *args,
		const struct fuse_operations *op, size_t op_size,
		char *mountpoint, void *user_data)
{
	struct fuse_chan *ch;
	struct fuse *fuse;
	int res;

	ch = fuse_mount(mountpoint, args);
	if (!ch)
		return NULL;

	fuse = fuse_new(ch, args, op, op_size, user_data);
	if (fuse == NULL)
		goto err_unmount;

	res = fuse_set_signal_handlers(fuse_get_session(fuse));
	if (res == -1)
		goto err_unmount;

	return fuse;

err_unmount:
	fuse_unmount(mountpoint, ch);
	if (fuse)
		fuse_destroy(fuse);
	return NULL;
}

static int mount_fuse(int argc, char **argv,
		      char **mountpoint,
		      int *multithreaded, int *foreground,
		      struct fuse **fuse)
{
	int err;
	struct spfs_context_s *ctx = get_context();
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	args.argc = argc;
	args.argv = argv;
	args.allocated = 0;

	err = fuse_parse_cmdline(&args, mountpoint, multithreaded, foreground);
	if (err)
		return err;

	if (!*mountpoint) {
		pr_err("%s: mountpoint wasn't specified\n", __func__);
		return -EINVAL;
	}

	pr_debug("%s: mountpoint  : %s\n", __func__, *mountpoint);

	/* Needed to return something, when stat for root in Sbut mode is
	 * called */
	err = stat(*mountpoint, &ctx->stub_root_stat);
	if (err < 0) {
		pr_perror("%s: failed to stat %s", __func__, *mountpoint);
		return err;
	}

	*fuse = setup_fuse(&args, &gateway_operations,
			  sizeof(gateway_operations), *mountpoint, NULL);
	if (*fuse == NULL) {
		pr_crit("failed to setup fuse at %s\n", *mountpoint);

		err = check_capabilities(1 << CAP_SYS_ADMIN, getpid());
		if (err == 0)
			pr_info("CAP_SYS_ADMIN is not set.\n");

		if (access("/sys/module/fuse", F_OK)) {
			pr_perror("failed to access /sys/module/fuse");
			if (errno == ENOENT)
				pr_err("FUSE module not loaded?\n");
		}
		return -1;
	}

	return 0;
}

static int mount_fuse_ns(int argc, char **argv,
		         char **mountpoint, int mnt_ns_pid,
		         int *multithreaded, int *foreground,
		         struct fuse **fuse)
{
	int err, mnt_ns_fd = -1;
	struct spfs_context_s *ctx = get_context();

	if (mnt_ns_pid) {
		mnt_ns_fd = open_ns(mnt_ns_pid, NS_MNT);
		if (mnt_ns_fd < 0)
			return mnt_ns_fd;

		err = set_ns(mnt_ns_fd);
		if (err)
			goto close_fd;
	}

	err = mount_fuse(argc, argv, mountpoint,
			 multithreaded, foreground,
			 fuse);

	if (mnt_ns_fd >= 0) {
		err = set_ns(ctx->mnt_ns_fd);
		if (err)
			goto teardown;
	}

close_fd:
	if (mnt_ns_fd >= 0)
		close(mnt_ns_fd);
	return err;

teardown:
	fuse_teardown(*fuse, *mountpoint);
	goto close_fd;

}

int main(int argc, char *argv[])
{
	char *proxy_dir = NULL;
	char *log_file = "/var/log/fuse_spfs.log";
	char *socket_path = "/var/run/fuse_control.sock";
	int ready_fd = -1, multithreaded, foreground, err, verbosity = 0;
	char *root = "", *mountpoint;
	bool single_user = false;
	int mnt_ns_pid = 0;
	int proxy_mnt_ns_pid = 0;
	spfs_mode_t mode = SPFS_STUB_MODE;
	struct fuse *fuse = NULL;

	if (parse_options(&argc, &argv, &proxy_dir, &mode, &log_file,
			  &socket_path, &verbosity, &root, &ready_fd,
			  &single_user, &mnt_ns_pid, &proxy_mnt_ns_pid))
		return -1;

	if (access("/dev/fuse", R_OK | W_OK)) {
		pr_perror("/dev/fuse is not accessible");
		return -1;
	}

	if (context_init(proxy_dir, proxy_mnt_ns_pid, mode, log_file,
			 socket_path, verbosity, single_user)) {
		pr_crit("failed to create gateway ctx\n");
		return -1;
	}

	pr_debug("%s: daemon      : %s\n", __func__, foreground ? "no" : "yes");
	pr_debug("%s: mode        : %d\n", __func__, mode);
	if (proxy_dir)
		pr_debug("%s: proxy_dir   : %s\n", __func__, proxy_dir);
	pr_debug("%s: log         : %s\n", __func__, log_file);
	pr_debug("%s: socket path : %s\n", __func__, socket_path);
	pr_debug("%s: root        : %s\n", __func__, root);
	pr_debug("%s: verbosity   : +%d\n", __func__, verbosity);

	err = mount_fuse_ns(argc, argv,
			    &mountpoint, mnt_ns_pid,
			    &multithreaded, &foreground,
			    &fuse);
	if (err) {
		pr_err("failed to mount fuse\n");
		goto destroy_context;
	}

	err = -1;
	if (start_socket_thread())
		goto teardown;

	if (secure_chroot(root))
		goto teardown;

	if (!foreground) {
		if (daemon(0, 0)) {
			pr_perror("failed to daemonize");
			goto teardown;
		}
	}

	pr_info("SPFS master started successfully\n");

	if (ready_fd != -1) {
		/* This is how SPFS indicates, that it's ready to acceps
		 * requests.
		 * If parent process would like to catch this moment, it has to
		 * poll for POLLHUP the passed fd, and once it's closed, check
		 * whether process is still alive wia waitpid with ECHILD. */
		pr_debug("closing fd %d\n", ready_fd);
		close(ready_fd);
	}

	if (multithreaded)
		err = fuse_loop_mt(fuse);
	else
		err = fuse_loop(fuse);

teardown:
	fuse_teardown(fuse, mountpoint);
destroy_context:
	context_fini();
	return (err == -1) ? 1 : 0;
}
