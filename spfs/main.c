#include "spfs_config.h"

#include <fuse.h>
#include <getopt.h>
#include <stdlib.h>

#include <sys/capability.h>

#include "include/log.h"
#include "include/util.h"
#include "include/ipc.h"

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
	printf("\t-m   --mode            work mode (\"stub\" or \"proxy\")\n");
	printf("\t-p   --proxy-dir       path for proxy mode\n");
	printf("\t-r   --root            directory to chroot to\n");
	printf("\t-l   --log             log file\n");
	printf("\t-s   --socket-path     control socket bind path\n");
	printf("\t-h   --help            print help (for double option will print fuse help)\n");
	printf("\t     --ready-fd        fd number to report ready status\n");
	printf("\t     --single-user     spfs won't close socket connection\n");
	printf("\t-v                     increase verbosity (can be used multiple times)\n");
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
		  int *verbosity, char **root, int *ready_fd, bool *single_user)
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
		{0,		0,			0,  0 }
	};
	int oind = 0, nind = 1;
	int argc = *orig_argc, new_argc = 0, prev_optind = 0, help_level = 0;
	char **argv = *orig_argv, **new_argv;
	char *mode_str = "stub";
	char *ready_fd_str = NULL;

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
		if (xatol(ready_fd_str, (long *)ready_fd) < 0) {
			pr_err("failed to convert --ready-fd\n");
			goto inval_args;
		}

		if (fcntl(*ready_fd, F_GETFD) == -1) {
			pr_err("fd %d is invalid\n", *ready_fd);
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

int main(int argc, char *argv[])
{
	char *proxy_dir = NULL;
	char *log_file = "/var/log/fuse_spfs.log";
	char *socket_path = "/var/run/fuse_control.sock";
	int ready_fd = -1, multithreaded, foreground, err, verbosity = 0;
	char *root = "", *mountpoint;
	bool single_user = false;
	spfs_mode_t mode = SPFS_STUB_MODE;
	struct fuse *fuse;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	if (parse_options(&argc, &argv, &proxy_dir, &mode, &log_file,
			  &socket_path, &verbosity, &root, &ready_fd,
			  &single_user))
		return -1;

	args.argc = argc;
	args.argv = argv;
	args.allocated = 0;

	if (fuse_parse_cmdline(&args, &mountpoint, &multithreaded, &foreground) == -1)
		return -1;

	if (access("/dev/fuse", R_OK | W_OK)) {
		pr_crit("/dev/fuse is not accessible");
		return -1;
	}

	if (context_init(proxy_dir, mode, log_file, socket_path, verbosity, mountpoint, single_user)) {
		pr_crit("failed to create gateway ctx\n");
		return -1;
	}

	pr_debug("%s: daemon      : %s\n", __func__, foreground ? "no" : "yes");
	pr_debug("%s: mode        : %d\n", __func__, mode);
	if (proxy_dir)
		pr_debug("%s: proxy_dir   : %s\n", __func__, proxy_dir);
	pr_debug("%s: log         : %s\n", __func__, log_file);
	pr_debug("%s: socket path : %s\n", __func__, socket_path);
	pr_debug("%s: mountpoint  : %s\n", __func__, mountpoint);
	pr_debug("%s: root        : %s\n", __func__, root);
	pr_debug("%s: verbosity   : +%d\n", __func__, verbosity);

	fuse = setup_fuse(&args, &gateway_operations,
			  sizeof(gateway_operations), mountpoint, NULL);
	if (fuse == NULL) {
		pr_crit("failed to setup fuse\n");

		err = check_capabilities(1 << CAP_SYS_ADMIN, getpid());
		if (err == 0)
			pr_info("CAP_SYS_ADMIN is not set.\n");
		return -1;
	}

	err = -1;
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
		pr_debug("closing fd %d\n");
		close(ready_fd);
	}

	if (multithreaded)
		err = fuse_loop_mt(fuse);
	else
		err = fuse_loop(fuse);

teardown:
	fuse_teardown(fuse, mountpoint);
	context_fini();
	return (err == -1) ? 1 : 0;
}
