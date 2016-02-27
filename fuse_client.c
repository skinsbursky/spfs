#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>


#include "interface.h"
#include "util.h"

static int send_data(int sock, void *ctx, size_t len)
{
	ssize_t bytes;
	int err;

	bytes = send(sock, ctx, len, MSG_EOR);
	if (bytes < 0) {
		printf("failed to send package: %d\n", -errno);
		return -1;
	}

	bytes = recv(sock, &err, sizeof(err), 0);
	if (bytes < 0) {
		printf("failed to receive reply: %d", -errno);
		return -1;
	}

	return err;
}

static int send_path(int sock, const char *path_to_send, const char *path_to_stat)
{
	size_t len;
	struct external_cmd *package;
	struct stat st;

	printf("stat \"%s\"\n", path_to_stat);
	if (stat(path_to_stat, &st) < 0) {
		printf("failed to stat %s\n", path_to_stat);
		return -1;
	}

	printf("sending \"%s\"\n", path_to_send);
	len = path_packet_size(path_to_send);

	package = malloc(len);
	if (!package) {
		printf("failed to allocate package\n");
		return -ENOMEM;
	}
	fill_path_packet(package, path_to_send, &st);

	return send_data(sock, package, len);
}

static int send_mode(int sock, int mode)
{
	size_t len;
	struct external_cmd *package;

	printf("changind mode to %d\n", mode);
	len = mode_packet_size(mode);

	package = malloc(len);
	if (!package) {
		printf("failed to allocate package\n");
		return -ENOMEM;
	}
	fill_mode_packet(package, mode);

	return send_data(sock, package, len);
}

static void help(char *program)
{
	printf("usage: %s command options\n", program);
	printf("\n");
	printf("commands:\n");
	printf("\tmode            allows to change mode work mode.\n");
	printf("\tpath            allows to send a path to be used in Golem mode.\n");
	printf("\n");
	printf("general options:\n");
	printf("\t-s   --socket_path     control socket bind path\n");
	printf("\t-h   --help            print help (for double option will print fuse help)\n");
	printf("\n");
	printf("Mode options:\n");
	printf("\t--mode            mode number (0: Proxy, 1: Stub, 2: Golem)\n");
	printf("\n");
	printf("Path options:\n");
	printf("\t--path_to_send    file path to send to FUSE\n");
	printf("\t--path_to_stat    file path to stat\n");
}

static int socket_create(const char *path)
{
	int sock, err;
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock < 0) {
		printf("Failed to create packet socket\n");
		return -1;
	}
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	err = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (err) {
		printf("failed to connect to socket %s\n", addr.sun_path);
		return -1;
	}
	return sock;
}

static int execude_path_cmd(int argc, char **argv)
{
	char *path_to_send = NULL, *path_to_stat = NULL;
	char *socket_path = NULL;
	static struct option opts[] = {
		{"path_to_send",	required_argument,	0,	1 },
		{"path_to_stat",	required_argument,	0,	2 },
		{"socket_path",		required_argument,	0,	3 },
		{"help",		no_argument,		0,	'h'},
		{0,			0,			0,	0 }
	};
	int sock;

	while (1) {
		char c;

		c = getopt_long(argc, argv, "h", opts, NULL);
		if (c == -1)
			break;

		switch (c) {
			case 1:
				path_to_send = optarg;
				break;
			case 2:
				path_to_stat = optarg;
				break;
			case 3:
				socket_path = optarg;
				break;
			case 'h':
				help(argv[0]);
				return 0;
			case '?':
				help(argv[0]);
				return 1;
		};
	}

	if (!path_to_send) {
		printf("Path to send wasn't provided\n");
		help(argv[0]);
		return 1;
	}

	if (!path_to_stat) {
		printf("Path to stat wasn't provided\n");
		help(argv[0]);
		return 1;
	}

	sock = socket_create(socket_path);
	if (sock < 0)
		return 1;

	return send_path(sock, path_to_send, path_to_stat);
}

static int convert_mode(const char *mode)
{
	char *endptr;
	long m;

	errno = 0;
	m = strtol(mode, &endptr, 10);
	if ((errno == ERANGE && (m == LONG_MAX || m == LONG_MIN))
			|| (errno != 0 && m == 0)) {
		perror("failed to convert mode");
		return -EINVAL;
	}

	if ((endptr == mode) || (*endptr != '\0')) {
		printf("Mode is not a number: '%s'\n", mode);
		return -EINVAL;
	}
	return m;
}

static int execude_mode_cmd(int argc, char **argv)
{
	char *mode = NULL;
	char *socket_path = NULL;
	static struct option opts[] = {
		{"mode",	required_argument,	0,	1 },
		{"socket_path",	required_argument,	0,	2 },
		{"help",	no_argument,		0,	'h'},
		{0,		0,			0,	0 }
	};
	int sock;
	long m;

	while (1) {
		char c;

		c = getopt_long(argc, argv, "h", opts, NULL);
		if (c == -1)
			break;

		switch (c) {
			case 1:
				mode = optarg;
				break;
			case 2:
				socket_path = optarg;
				break;
			case 'h':
				help(argv[0]);
				return 0;
			case '?':
				printf("unknown option: %s\n", argv[optind]);
				help(argv[0]);
				return 1;
		};
	}

	if (!mode) {
		printf("Mode wasn't provided\n");
		help(argv[0]);
		return 1;
	}

	if (!socket_path) {
		printf("Socket path wasn't provided\n");
		help(argv[0]);
		return 1;
	}

	m = convert_mode(mode);
	if (m < 0) {
		help(argv[0]);
		return 1;
	}

	sock = socket_create(socket_path);
	if (sock < 0)
		return 1;

	return send_mode(sock, m);
}


int main(int argc, char **argv)
{
	if (!strcmp(argv[1], "mode"))
		return execude_mode_cmd(argc, argv);
	else if (!strcmp(argv[1], "path"))
		return execude_path_cmd(argc, argv);
	printf("Unknown command: %s\n", argv[1]);
	help(argv[0]);
	return 1;
}
