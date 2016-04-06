#include "spfs_config.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sched.h>
#include <limits.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>

#include "include/util.h"
#include "include/log.h"
#include "include/socket.h"

#include "spfs/context.h"

#include "context.h"

static struct spfs_manager_context_s spfs_manager_context = {
	.spfs_root = "",
};

static int join_cgroups(char *cgroups)
{
	return 0;
}

static int join_one_namespace(int pid, const char *ns, int ns_type)
{
	int ns_fd;
	char *path;
	int err = 0;

	path = xsprintf("/proc/%d/ns/%s", pid, ns);
	if (!path)
		return -ENOMEM;

	ns_fd = open(path, O_RDONLY);
	if (ns_fd < 0) {
		pr_perror("failed to open %s", path);
		err = -errno;
		goto free_path;
	}

	if (setns(ns_fd, ns_type) < 0) {
		pr_perror("Can't switch %s ns", ns);
		err = -errno;
	}

	close(ns_fd);
free_path:
	free(path);
	return err;
}

static int get_namespace_type(const char *ns)
{
	if (!strcmp(ns, "user"))
		return CLONE_NEWUSER;
	if (!strcmp(ns, "mnt"))
		return CLONE_NEWNS;
	if (!strcmp(ns, "net"))
		return CLONE_NEWNET;
	if (!strcmp(ns, "pid"))
		return CLONE_NEWPID;
	if (!strcmp(ns, "uts"))
		return CLONE_NEWPID;
	if (!strcmp(ns, "ipc"))
		return CLONE_NEWIPC;

	pr_err("unknown namespace: %s\n", ns);
	return -EINVAL;
}

int join_namespaces(int pid, const char *namespaces)
{
	char *ns, *ns_list;
	int err = 0;

	pr_debug("Join process %d namespaces: %s\n", pid, namespaces);

	ns_list = strdup(namespaces);
	if (!ns_list) {
		pr_err("failed to duplicate namespaces\n");
		return -ENOMEM;
	}

	while ((ns = strsep(&ns_list, ",")) != NULL) {
		int ns_type, err;

		ns_type = get_namespace_type(ns);
		if (ns_type < 0) {
			err = ns_type;
			goto free_ns_list;
		}

		err = join_one_namespace(pid, ns, ns_type);
		if (err)
			goto free_ns_list;

		pr_debug("joined %s namespace of process %d\n", ns, pid);
	}

free_ns_list:
	free(ns_list);
	return err;
}

static void sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	pid_t pid;
	int status;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status))
			pr_info("%d exited, status=%d\n", pid, WEXITSTATUS(status));
		else
			pr_err("%d killed by signal %d (%s)\n", pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
	}

	if ((pid < 0) && (errno != ECHILD))
		pr_perror("failed to collect pid");
}

static int setup_signal_handlers(struct spfs_manager_context_s *ctx)
{
	struct sigaction act;
	sigset_t blockmask;
	int err;

	sigfillset(&blockmask);
	sigdelset(&blockmask, SIGCHLD);

	err = sigprocmask(SIG_SETMASK, &blockmask, NULL);
	if (err < 0) {
		pr_perror("Can't block signals");
		return -1;
	}

	act.sa_flags = SA_NOCLDSTOP | SA_SIGINFO | SA_RESTART;
	act.sa_sigaction = sigchld_handler;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGCHLD);

	err = sigaction(SIGCHLD, &act, NULL);
	if (err < 0) {
		pr_perror("sigaction() failed");
		return -1;
	}
	return 0;
}

static int configure(struct spfs_manager_context_s *ctx)
{
	int err;

	if (!ctx->work_dir) {
		pr_err("work directory wasn't provided\n");
		return -EINVAL;
	}

	if (!ctx->spfs_dir) {
		pr_err("spfs directory wasn't provided\n");
		return -EINVAL;
	}

	if (!ctx->mountpoint) {
		pr_err("mountpoint wasn't provided\n");
		return -EINVAL;
	}

	if (strlen(ctx->spfs_root) && ctx->spfs_root[strlen(ctx->spfs_root)-1] != '/') {
		ctx->spfs_root = xsprintf("%s/", ctx->spfs_root);
		if (!ctx->spfs_root) {
			pr_err("failed to allocate\n");
			return -ENOMEM;
		}
	}

	if (create_dir(ctx->work_dir))
		return -1;

	if (!ctx->socket_path) {
		ctx->socket_path = xsprintf("%s/%s.sock", ctx->work_dir, ctx->progname);
		if (!ctx->socket_path) {
			pr_err("failed to allocate\n");
			return -ENOMEM;
		}
		pr_info("socket path wasn't provided: using %s\n", ctx->socket_path);
	}

	if (!access(ctx->socket_path, X_OK)) {
		pr_err("socket %s already exists. Stale?", ctx->socket_path);
		return -EINVAL;
	}

	if (ctx->start_mode) {
		if (spfs_mode(ctx->start_mode, ctx->proxy_dir) < 0)
			return -EINVAL;
	}

	if (!ctx->log_file) {
		ctx->log_file = xsprintf("%s/%s.log", ctx->work_dir, ctx->progname);
		if (!ctx->log_file) {
			pr_err("failed to allocate\n");
			return -ENOMEM;
		}
		pr_info("log path wasn't provided: using %s\n", ctx->log_file);
	}

	if (setup_log(ctx->log_file, ctx->verbosity))
		return -1;

	ctx->sock = seqpacket_sock(ctx->socket_path, true, true, NULL);
	if (ctx->sock < 0)
		return ctx->sock;

	if (ctx->cgroups) {
		err = join_cgroups(ctx->cgroups);
		if (err)
			return err;
	}

	if (ctx->process_id) {
		pr_debug("Join process %s context\n", ctx->process_id);

		err = xatol(ctx->process_id, &ctx->ns_pid);
		if (err < 0)
			return -EINVAL;

		if (!ctx->namespaces) {
			pr_err("Pid was specified, but no namespaces provided\n");
			return -EINVAL;
		}
	}

	if (access(ctx->mountpoint, R_OK | W_OK)) {
		pr_perror("mountpoint %s is not accessible for RW", ctx->mountpoint);
		return -EINVAL;
	}

	if (setup_signal_handlers(ctx))
		return -1;

	return 0;
}

static void help(const char *program)
{
	printf("usage: %s [options] mountpoint\n", program);
	printf("\n");
	printf("general options:\n");
	printf("\t-w   --work-dir        working directory\n");
	printf("\t-l   --log             log file\n");
	printf("\t-s   --socket-path     interface socket path\n");
	printf("\t-d   --daemon          daemonize\n");
	printf("\t-p   --pid             pid of the process to join\n");
	printf("\t     --namespaces      list of namespaces to join\n");
	printf("\t     --cgroups         list of cgroups to join\n");
	printf("\t     --spfs-mode       spfs start mode\n");
	printf("\t     --spfs-proxy      path for spfs in proxy mode\n");
	printf("\t     --spfs-dir        spfs working directory\n");
	printf("\t     --spfs-root       directory for spfs to chroot to\n");
	printf("\t-h   --help            print this help and exit\n");
	printf("\t-v                     increase verbosity (can be used multiple times)\n");
	printf("\n");
}

static int parse_options(int argc, char **argv, char **start_mode, char **spfs_dir,
			 char **work_dir, char **log, char **socket_path,
			 int *verbosity, bool *daemonize, char **pid, char **spfs_root,
			 char **namespaces, char **cgroups, char **proxy_dir,
			 char **mountpoint)
{
	static struct option opts[] = {
		{"work-dir",	required_argument,      0, 'w'},
		{"log",         required_argument,      0, 'l'},
		{"socket-path",	required_argument,      0, 's'},
		{"daemon",	required_argument,      0, 'd'},
		{"pid",		required_argument,      0, 'p'},
		{"namespaces",	required_argument,      0, 1000},
		{"cgroups",	required_argument,      0, 1001},
		{"spfs-proxy",	required_argument,      0, 1002},
		{"spfs-root",   required_argument,      0, 1003},
		{"spfs-mode",	required_argument,      0, 1004},
		{"spfs-dir",	required_argument,      0, 1005},
		{"help",        no_argument,            0, 'h'},
		{0,             0,                      0,  0 }
	};

	while (1) {
		int c;

		c = getopt_long(argc, argv, "w:l:s:p:vhd", opts, NULL);
		if (c == -1)
			break;

		switch (c) {
			case 'w':
				*work_dir = optarg;
				break;
			case 'l':
				*log = optarg;
				break;
			case 's':
				*socket_path = optarg;
				break;
			case 'v':
				*verbosity += 1;
				break;
			case 'd':
				*daemonize = true;
				break;
			case 'p':
				*pid = optarg;
				break;
			case 1000:
				*namespaces = optarg;
				break;
			case 1001:
				*cgroups = optarg;
				break;
			case 1002:
				*proxy_dir = optarg;
				break;
			case 1003:
				*spfs_root = optarg;
				break;
			case 1004:
				*start_mode = optarg;
				break;
			case 1005:
				*spfs_dir = optarg;
				break;
			case 'h':
				help(argv[0]);
				exit(EXIT_SUCCESS);
                        case '?':
				help(argv[0]);
				exit(EXIT_FAILURE);
			default:
				pr_err("getopt returned character code: 0%o\n", c);
				exit(EXIT_FAILURE);

		}
	}

	if (optind < argc)
		*mountpoint = argv[optind++];

	if (optind < argc) {
		pr_err("only one mountpoint can be provided\n");
		return -EINVAL;
	}

	return 0;
}

static void cleanup(void)
{
	if (spfs_manager_context.sock) {
		/* We assume, that:
		 * 1) Is sock is non-zero, then socket path was initialized
		 * 2) Sock fd was moved about standart descriptors region.
		 */
		if (unlink(spfs_manager_context.socket_path))
			pr_perror("failed ot unlink %s", spfs_manager_context.socket_path);
	}
}

extern const char *__progname;

struct spfs_manager_context_s *create_context(int argc, char **argv)
{
	struct spfs_manager_context_s *ctx = &spfs_manager_context;

	ctx->progname = __progname;

	(void) close_inherited_fds();

	if (parse_options(argc, argv, &ctx->start_mode, &ctx->spfs_dir, &ctx->work_dir, &ctx->log_file,
			  &ctx->socket_path, &ctx->verbosity, &ctx->daemonize,
			  &ctx->process_id, &ctx->spfs_root, &ctx->namespaces, &ctx->cgroups,
			  &ctx->proxy_dir, &ctx->mountpoint)) {
		pr_err("failed to parse options\n");
		return NULL;
	}

	if (atexit(cleanup)) {
		pr_err("failed to register cleanup function\n");
		return NULL;
	}

	if (configure(ctx)) {
		pr_err("failed to configure\n");
		return NULL;
	}

	return ctx;
}
