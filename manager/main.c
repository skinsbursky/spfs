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

#include "include/interface.h"
#include "include/util.h"
#include "include/log.h"
#include "include/socket.h"

char *work_dir;
char *log_file;
char *socket_path;
int verbosity;
bool daemonize;
char *process_id;
char *namespaces;
char *cgroups;
char *mountpoint;

static int spfs_manager_conn_handler(int sock, void *data)
{
	pr_err("Interface is not ready yet\n");
	return -ENOENT;
}

static int mount_spfs(const char *work_dir, char *mountpoint)
{
	int pid, status;
	const char *spfs = "fuse_stub";
	char *proxy_dir;
	char *socket_path;
	char *log_path;
	/*TODO Add spfs_mode option? */
	/* TODO make mode accepf strings like "stub" or "proxy" ? */
	char *mode = "1";

	log_path = xsprintf("%s/spfs.log", work_dir);
	if (!log_path)
		return -ENOMEM;

	socket_path = xsprintf("%s/spfs.sock", work_dir);
	if (!socket_path)
		return -ENOMEM;

	proxy_dir = xsprintf("%s/mnt", work_dir);
	if (!proxy_dir)
		return -ENOMEM;

	if (mkdir(proxy_dir, 0755) && (errno != EEXIST)) {
		pr_perror("failed to create %s", proxy_dir);
		return -errno;
	}

	pr_debug("%s: 2\n", __func__);

	pid = fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			return -errno;
		case 0:
			execvp(spfs, (char *[]){ "spfs", "-vvvv",
				/* TODO start with STUB mode and feed with proper directory later */
//				"--proxy_dir", proxy_dir,
				"--mode", mode,
				"--socket_path", socket_path,
				"--log", log_path,
				mountpoint, NULL });

			pr_perror("exec failed");
			_exit(EXIT_FAILURE);
	}

	free(socket_path);
	free(log_path);
	free(proxy_dir);

	pid = waitpid(pid, &status, 0);
	if (pid < 0) {
		pr_perror("Wait for %d failed", pid);
		return -errno;
	}

	if (WIFSIGNALED(status)) {
		pr_err("Spfs with pid %d was killed by %d\n", pid, WTERMSIG(status));
		return -ECANCELED;
	}

	if (WEXITSTATUS(status)) {
		pr_err("Spfs with pid %d exited with error %d\n", pid, WEXITSTATUS(status));
		return WEXITSTATUS(status);
	}

	pr_info("%s: spfs on %s started successfully\n", __func__, mountpoint);
	return WEXITSTATUS(status);
}

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

static int join_namespaces(int pid, char *namespaces)
{
	char *ns;

	while ((ns = strsep(&namespaces, ",")) != NULL) {
		int ns_type;
		int err;

		ns_type = get_namespace_type(ns);
		if (ns_type < 0)
			return -EINVAL;

		err = join_one_namespace(pid, ns, ns_type);
		if (err)
			return err;

		pr_debug("joined %s namespace of process %d\n", ns, pid);
	}
	return 0;
}

static int convert_pid(const char *process_id)
{
	char *endptr;
	long pid;

	errno = 0;
	pid = strtol(process_id, &endptr, 10);
	if ((errno == ERANGE && (pid == LONG_MAX || pid == LONG_MIN))
			|| (errno != 0 && pid == 0)) {
		perror("failed to convert process_id");
		return -EINVAL;
	}

	if ((endptr == process_id) || (*endptr != '\0')) {
		printf("Mode is not a number: '%s'\n", process_id);
		return -EINVAL;
	}
	return pid;
}

static int setup_log(const char *log_file)
{
	/* TODO: set O_CLOEXEC */
	return 0;
}

static int configure(char *work_dir, char *log, char *socket_path,
		     int verbosity, char *process_id,
		     char *namespaces, char *cgroups, char *mountpoint)
{
	int err, sock;

	if (!socket_path) {
		pr_err("socket path wasn't provided\n");
		return -EINVAL;
	}

	if (!access(socket_path, X_OK)) {
		pr_perror("socket %s already exists. Stale?", socket_path);
		return -EINVAL;
	}

	if (!mountpoint) {
		pr_err("mountpoint wasn't provided\n");
		return -EINVAL;
	}

	err = setup_log(log);
	if (err)
		return err;

	sock = sock_seqpacket(socket_path, true, true, NULL);
	if (sock < 0)
		return sock;

	if (cgroups) {
		err = join_cgroups(cgroups);
		if (err)
			return err;
	}

	if (process_id) {
		int pid;

		pid = convert_pid(process_id);
		if (pid < 0)
			return -EINVAL;

		if (!namespaces) {
			pr_err("Pid was specified, but no namespaces provided\n");
			return -EINVAL;
		}

		err = join_namespaces(pid, namespaces);
		if (err)
			return err;
	}

	/* Check work directory and mountpoint _after_ namespaces to satisfy
	 * mount namespace if provided */
	if (mkdir(work_dir, 0755) && (errno != EEXIST)) {
		pr_perror("failed to create %s", work_dir);
		return -errno;
	}
#if 0
	if (access(work_dir, R_OK | W_OK)) {
		pr_perror("directory %s is not accessible for rw", work_dir);
		return -EINVAL;
	}
#endif
	if (access(mountpoint, R_OK | W_OK)) {
		pr_perror("mountpoint %s is not accessible\n");
		return -EINVAL;
	}

	return sock;
}

static void help(const char *program)
{
	printf("usage: %s [options] mountpoint\n", program);
	printf("\n");
	printf("general options:\n");
	printf("\t-p   --work_dir        spfs working directory\n");
	printf("\t-l   --log             log file\n");
	printf("\t-s   --socket_path     interface socket path\n");
	printf("\t-d   --daemon          daemonize\n");
	printf("\t-p   --pid             pid of the process to join\n");
	printf("\t     --namespaces      list of namespaces to join\n");
	printf("\t     --cgroups         list of cgroups to join\n");
	printf("\t-h   --help            print this help and exit\n");
	printf("\t-v                     increase verbosity (can be used multiple times)\n");
	printf("\n");
}

static int parse_options(int argc, char **argv,
			 char **work_dir, char **log, char **socket_path,
			 int *verbosity, bool *daemonize, char **pid,
			 char **namespaces, char **cgroups, char **mountpoint)
{
	static struct option opts[] = {
		{"work_dir",	required_argument,      0, 'w'},
		{"log",         required_argument,      0, 'l'},
		{"socket_path",	required_argument,      0, 's'},
		{"daemon",	required_argument,      0, 'd'},
		{"pid",		required_argument,      0, 'p'},
		{"namespaces",	required_argument,      0, 1000},
		{"cgroups",	required_argument,      0, 1001},
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
	if (socket_path)
		if (unlink(socket_path))
			pr_perror("failed ot unlink %s", socket_path);
}

int main(int argc, char *argv[])
{
	int sock;

	if (parse_options(argc, argv, &work_dir, &log_file, &socket_path,
			&verbosity, &daemonize, &process_id, &namespaces,
			&cgroups, &mountpoint)) {
		pr_err("failed to parse options\n");
		return -1;
	}

	if (atexit(cleanup)) {
		pr_err("failed to register cleanup function\n");
		return -1;
	}

	sock = configure(work_dir, log_file, socket_path, verbosity, process_id,
			 namespaces, cgroups, mountpoint);
	if (sock < 0)
		return sock;

	if (mount_spfs(work_dir, mountpoint))
		return -EINVAL;

	if (daemonize) {
		if (daemon(0, 0)) {
			pr_perror("failed to daemonize");
			return -errno;
		}
	}

	return socket_loop(sock, NULL, spfs_manager_conn_handler);
}
