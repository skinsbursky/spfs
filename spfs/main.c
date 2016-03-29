#include "spfs_config.h"

#include <fuse.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <sys/wait.h>

#include "include/log.h"
#include "include/util.h"

#include "context.h"

extern struct fuse_operations gateway_operations;

static void copy_args(char **old, int *old_index, char **new, int *new_index)
{
	while (*old_index < optind) {
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
	printf("\t-m   --mode            work mode\n");
	printf("\t-p   --proxy-dir       path for proxy mode\n");
	printf("\t-l   --log             log file\n");
	printf("\t-s   --socket-path     control socket bind path\n");
	printf("\t-h   --help            print help (for double option will print fuse help)\n");
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
		  char **proxy_dir, long *mode, char **log, char **socket_path,
		  int *verbosity)
{
	static struct option opts[] = {
		{"proxy-dir",	required_argument,	0, 'p'},
		{"mode",	required_argument,	0, 'm'},
		{"log",		required_argument,	0, 'l'},
		{"socket-path",	required_argument,	0, 's'},
		{"help",	no_argument,		0, 'h'},
		{0,		0,			0,  0 }
	};
	int oind = 0, nind = 1;
	int argc = *orig_argc, new_argc = 0, prev_optind = 0, help_level = 0;
	char **argv = *orig_argv, **new_argv;

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
		char c;

		c = getopt_long(argc, argv, "p:l:m:s:vh", opts, &oind);
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
				if (xatol(optarg, mode)) {
					pr_err("mode is invalid\n");
					return -EINVAL;
				}
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
			case 'v':
				if (optind > prev_optind)
					nind += 1;
				*verbosity += 1;
				break;
			case 'h':
				if (help_level++)
					new_argv[new_argc++] = "-h";
				break;
			case '?':
				pr_debug("copy fuse option \"%s\"\n", argv[optind-1]);
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

	if ((*mode == SPFS_PROXY_MODE) && (!*proxy_dir)) {
		pr_crit("Proxy directory must be specified\n");
		return -EINVAL;
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
}

static int my_fuse_daemonize(int foreground)
{
	(void) chdir("/");

	/* TODO: foreground mode doesn't work because of fork. Either fix it of
	 * drop it. */
	if (!foreground) {
		int nullfd;

		if (setsid() == -1) {
			perror("fuse_daemonize: setsid");
			return -1;
		}

		nullfd = open("/dev/null", O_RDWR, 0);
		if (nullfd != -1) {
			(void) dup2(nullfd, 0);
			(void) dup2(nullfd, 1);
			(void) dup2(nullfd, 2);
			if (nullfd > 2)
				close(nullfd);
		}
	}
	return 0;
}

static struct fuse *setup_fuse(int argc, char *argv[],
		const struct fuse_operations *op, size_t op_size,
		char **mountpoint, int *multithreaded, void *user_data)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_chan *ch;
	struct fuse *fuse;
	int foreground;
	int res;

	res = fuse_parse_cmdline(&args, mountpoint, multithreaded, &foreground);
	if (res == -1)
		return NULL;

	res = context_store_mnt_stat(*mountpoint);
	if (res)
		return NULL;

	ch = fuse_mount(*mountpoint, &args);
	if (!ch) {
		fuse_opt_free_args(&args);
		goto err_free;
	}

	fuse = fuse_new(ch, &args, op, op_size, user_data);
	fuse_opt_free_args(&args);
	if (fuse == NULL)
		goto err_unmount;

	res = my_fuse_daemonize(foreground);
	if (res == -1)
		goto err_unmount;

	res = fuse_set_signal_handlers(fuse_get_session(fuse));
	if (res == -1)
		goto err_unmount;

	return fuse;

err_unmount:
	fuse_unmount(*mountpoint, ch);
	if (fuse)
		fuse_destroy(fuse);
err_free:
	free(*mountpoint);
	return NULL;
}

static int report_to_parent(int pipe, int res)
{
	if (write(pipe, &res, sizeof(res)) < 0) {
		pr_perror("failed to write to fd %d", pipe);
		return -errno;
	}
	close(pipe);
	return 0;
}

static int mount_fuse(const char *proxy_dir, int mode, const char *log_file,
		      const char *socket_path, int pipe, int verbosity,
		      int argc, char *argv[])
{
	int err;
	struct fuse *fuse;
	char *mountpoint;
	int multithreaded;

	err = context_init(proxy_dir, mode, log_file, socket_path, verbosity);
	if (err) {
		pr_crit("failed to create gateway ctx\n");
		goto err;
	}

	if (access("/dev/fuse", R_OK | W_OK)) {
		pr_crit("/dev/fuse is not accessible");
		goto err;
	}

	fuse = setup_fuse(argc, argv,
			  &gateway_operations, sizeof(gateway_operations),
			  &mountpoint, &multithreaded, NULL);
	if (fuse == NULL) {
		pr_crit("failed to setup fuse\n");
		goto destroy_ctx;
	}

	if (report_to_parent(pipe, 0) < 0) {
		pr_crit("failed to send report to parent\n");
		goto teardown;
	}

	if (multithreaded)
		err = fuse_loop_mt(fuse);
	else
		err = fuse_loop(fuse);

teardown:
	fuse_teardown(fuse, mountpoint);
	context_fini();
	return (err == -1) ? 1 : 0;

destroy_ctx:
	context_fini();
err:
	report_to_parent(pipe, -1);
	return -1;
}


static int poll_child_status(int pipe)
{
	struct pollfd pfd = {
		.fd = pipe,
		.events = POLLIN | POLLERR | POLLHUP,
		.revents = 0,
	};
	int timeout_ms = 5000;
	int res;

	res = poll(&pfd, 1, timeout_ms);
	if (res < 0) {
		res = -errno;
		pr_crit("poll returned %d\n", errno);
		return res;
	}

	if (!res) {
		pr_crit("Child wasn't ready for %d ms.\n"
		       "Something bad happened\n", timeout_ms);
		return -ETIMEDOUT;
	}
	if (pfd.revents & POLLIN)
		return 0;

	if (pfd.revents & POLLERR)
		pr_crit("poll return POLERR\n");
	else if (pfd.revents & POLLHUP)
		pr_crit("poll return POLHUP\n");
	return -1;
}

static int kill_child_and_collect(int pid)
{
	int status;
	int signal = SIGKILL;

	pr_info("Killing child %d\n", pid);
	if (kill(pid, signal)) {
		switch (errno) {
			case EINVAL:
				pr_err("Wrong signal?!\n");
				return -EINVAL;
			case EPERM:
				pr_err("Can't kill own child?!\n");
				return -EPERM;
			case ESRCH:
				pr_err("Process doesn't exist (or dead).\n");
				break;
		}
	}
	pid = waitpid(pid, &status, 0);
	if (pid < 0) {
		pr_perror("Wait for %d failed", pid);
		return -errno;
	}

	if (WIFEXITED(status))
		pr_info("Child exited with the following reason: %d\n", WEXITSTATUS(status));
	else
		pr_info("Child was killed by signal %d\n", WTERMSIG(status));
	return -1;
}

static int wait_child_report(int pipe)
{
	int err;

	err = poll_child_status(pipe);
	if (!err) {
		if (read(pipe, &err, sizeof(int)) < 0) {
			pr_perror("failed to read from control pipe");
			err = -errno;
		}
	}
	return err;
}

int main(int argc, char *argv[])
{
	char *proxy_dir = NULL;
	char *log_file = "/var/log/fuse_spfs.log";
	char *socket_path = "/var/run/fuse_control.sock";
	long mode = SPFS_STUB_MODE;
	pid_t pid;
	int err, pipes[2], verbosity = 0;

	if (parse_options(&argc, &argv, &proxy_dir, &mode, &log_file,
			  &socket_path, &verbosity))
		return -1;

	/* This is the control pipe, used to inform parent, that child
	 * succeeded initialization phase and parent can exit. After exit the
	 * child will be reparented to init and become a daemon.
	 * One might ask, why tht pipe is needed? Isn't it enough to wait for
	 * child, which, in turn will call daemonize(), when initialization
	 * phase is over?
	 * Unfortunatelly, fuse process (child) will need to create another
	 * thread to server control socket. Thus daemonize() can't be used (new
	 * child will be the only thread).
	 * Node: creation of a socket thread can fail and it
	 * won't be possible to catch this error after daemonize().
	 * So, this solution is a bit different: child will report it's state
	 * via pipe.
	 */
	if (pipe(pipes) < 0) {
		pr_crit("failed to create info pipe\n");
		return -1;
	}

	pid = fork();
	switch (pid) {
		case -1:
			pr_crit("failed to fork fuse master\n");
			return -1;
		case 0:
			close(pipes[0]);
			return mount_fuse(proxy_dir, mode, log_file,
					  socket_path, pipes[1], verbosity,
					  argc, argv);
	}

	close(pipes[1]);

	err = wait_child_report(pipes[0]);
	if (err) {
		pr_crit("Child failed to initialize: %d\n", err);
		pr_info("See %s\n", log_file);
		return kill_child_and_collect(pid);
	}
	pr_info("Fuse master started successfully with pid %d\n", pid);
	if (proxy_dir)
		pr_debug("%s: proxy_dir   : %s\n", __func__, proxy_dir);
	pr_debug("%s: mode        : %d\n", __func__, mode);
	pr_debug("%s: log         : %s\n", __func__, log_file);
	pr_debug("%s: socket path : %s\n", __func__, socket_path);
	pr_debug("%s: verbosity   : +%d\n", __func__, verbosity);

	return 0;
}
