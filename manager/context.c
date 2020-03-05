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

#include <sys/mman.h>

#include "include/util.h"
#include "include/log.h"
#include "include/socket.h"
#include "include/shm.h"

#include "spfs/context.h"

#include "context.h"
#include "spfs.h"
#include "replace.h"

static struct spfs_manager_context_s spfs_manager_context;

const int *mgr_ns_fds(void)
{
	return spfs_manager_context.ns_fds;
}

const char *mgr_work_dir(void)
{
	return spfs_manager_context.work_dir;
}

const char *mgr_ovz_id(void)
{
	return spfs_manager_context.ovz_id;
}

static void cleanup_spfs_mount(struct spfs_manager_context_s *ctx,
			       struct spfs_info_s *info, int status)
{
	bool failed = WIFSIGNALED(status) || !!WEXITSTATUS(status);

	pr_debug("removing info %s from the list (replacer pid %d)\n",
		  info->mnt.id, info->replacer);

	if (failed) {
		/* SPFS master was failed. We need to release the reference */
		spfs_release_mnt(info);
		if (info->replacer > 0 && kill(info->replacer, SIGKILL))
			pr_perror("Failed to kill replacer");
	}

	info->dead = true;
	del_spfs_info(ctx->spfs_mounts, info);

	if (unlink(info->socket_path))
		pr_perror("failed to unlink %s", info->socket_path);

	spfs_cleanup_env(info, failed);

	close_namespaces(info->ns_fds);
}

static inline void pr_term_mnt_service_info(pid_t pid, int status, const char *mnt, const char* tag)
{
	if (WIFEXITED(status))
		pr_debug("spfs (mnt_id %s) %s (pid %d) exited, status=%d\n", mnt, tag, pid, WEXITSTATUS(status));
	else
		pr_err("spfs (mnt_id %s) %s (pid %d) killed by signal %d (%s)\n", mnt, tag, pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
}

static void sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	struct spfs_manager_context_s *ctx = &spfs_manager_context;
	pid_t pid;
	int status;

	log_ts_control(false);

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		struct spfs_info_s *info;

		if ((info = find_spfs_by_replacer(ctx->spfs_mounts, pid))) {
			if (WEXITSTATUS(status) == 0)
				/* SPFS has been successfully replaced.
				 * Now we can release spfs mount by closing
				 * corresponding fd.
				 */
				spfs_release_mnt(info);

			pr_term_mnt_service_info(pid, status, info->mnt.id, "replacer");
			info->replacer = -1;
		} else if ((info = find_spfs_by_pid(ctx->spfs_mounts, pid))) {
			pr_term_mnt_service_info(pid, status, info->mnt.id, "master");

			cleanup_spfs_mount(ctx, info, status);
			if (list_empty(&ctx->spfs_mounts->list) && ctx->exit_with_spfs) {
				pr_info("spfs list is empty. Exiting.\n");
				exit(0);
			}
		} else {
			pr_term_mnt_service_info(pid, status, "unknown", "unknown");
		}
	}

	if ((pid < 0) && (errno != ECHILD))
		pr_perror("failed to collect pid");

	log_ts_control(true);
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
	if (!ctx->work_dir) {
		ctx->work_dir = xsprintf("/run/%s-%d", ctx->progname, getpid());
		if (!ctx->work_dir) {
			pr_err("failed to allocate string\n");
			return -ENOMEM;
		}
	}
	pr_info("working directory: %s\n", ctx->work_dir);

	if (create_dir(ctx->work_dir))
		return -1;

	if (chdir(ctx->work_dir)) {
		pr_perror("failed to chdir into %s", ctx->work_dir);
		return -EINVAL;
	}

	if (!ctx->socket_path) {
		ctx->socket_path = xsprintf("%s.sock", ctx->progname);
		if (!ctx->socket_path) {
			pr_err("failed to allocate\n");
			return -ENOMEM;
		}
		pr_info("socket path wasn't provided: using %s/%s\n",
				ctx->work_dir, ctx->socket_path);
	} else
		pr_info("socket path: %s\n", ctx->socket_path);

	if (!access(ctx->socket_path, X_OK)) {
		pr_err("socket %s already exists. Stale?\n", ctx->socket_path);
		return -EINVAL;
	}

	if (!ctx->log_file) {
		const char *log_dir = ".";

		if (ctx->log_dir) {
			log_dir = ctx->log_dir;
			if (create_dir(log_dir))
				return -1;
		}

		ctx->log_file = xsprintf("%s/%s.log", log_dir, ctx->progname);
		if (!ctx->log_file) {
			pr_err("failed to allocate\n");
			return -ENOMEM;
		}
		pr_info("log path wasn't provided: using %s/%s\n",
				ctx->work_dir, ctx->log_file);
	} else
		pr_info("log path: %s\n", ctx->socket_path);

	if (setup_log(ctx->log_file, ctx->verbosity))
		return -1;

	ctx->sock = seqpacket_sock(ctx->socket_path, true, true, NULL);
	if (ctx->sock < 0)
		return ctx->sock;

	if (setup_signal_handlers(ctx))
		return -1;

	if (shm_init_pool())
		return -1;

	ctx->spfs_mounts = create_shared_list();
	if (!ctx->spfs_mounts)
		return -1;

	ctx->freeze_cgroups = create_shared_list();
	if (!ctx->freeze_cgroups)
		return -1;

	if (open_namespaces(getpid(), ctx->ns_fds))
		return -1;

	ctx->ovz_id = getenv("VEID");

	return 0;
}

static void help(const char *program)
{
	printf("usage: %s [options]\n", program);
	printf("\n");
	printf("general options:\n");
	printf("\t-w   --work-dir        working directory\n");
	printf("\t-l   --log             log file\n");
	printf("\t-s   --socket-path     interface socket path\n");
	printf("\t-d   --daemon          daemonize\n");
	printf("\t     --exit-with-spfs  exit, when spfs has exited\n");
	printf("\t-h   --help            print this help and exit\n");
	printf("\t-v                     increase verbosity (can be used multiple times)\n");
	printf("\n");
}

static int parse_options(int argc, char **argv, char **work_dir, char **log,
			 char **log_dir, char **socket_path, int *verbosity,
			 bool *daemonize, bool *exit_with_spfs)
{
	static struct option opts[] = {
		{"work-dir",		required_argument,      0, 'w'},
		{"log-dir",		required_argument,      0, 'L'},
		{"log",			required_argument,      0, 'l'},
		{"socket-path",		required_argument,      0, 's'},
		{"daemon",		required_argument,      0, 'd'},
		{"exit-with-spfs",	no_argument,		0, 1000},
		{"help",		no_argument,		0, 'h'},
		{0,			0,			0,  0 }
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
			case 'L':
				*log_dir = optarg;
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
			case 1000:
				*exit_with_spfs = true;
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

	if (optind < argc) {
		pr_err("trailing parameter: %s\n", argv[optind]);
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

	if (parse_options(argc, argv, &ctx->work_dir, &ctx->log_file,
				&ctx->log_dir, &ctx->socket_path,
				&ctx->verbosity, &ctx->daemonize,
				&ctx->exit_with_spfs)) {
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
