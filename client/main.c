#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "spfs/interface.h"
#include "spfs/context.h"
#include "manager/interface.h"

#include "include/util.h"
#include "include/socket.h"

static int send_mount(const char *socket_path, const char *source, const char *type,
		      unsigned long mountflags, const char *options)
{
	size_t len;
	struct external_cmd *package;
	int err;

	printf("mounting %s with flags %ld and options '%s'\n", type,
			mountflags, options);

	len = mount_packet_size(source, type, options);

	package = malloc(len);
	if (!package) {
		printf("failed to allocate package\n");
		return -ENOMEM;
	}
	fill_mount_packet(package, source, type, options, mountflags);

	err = send_packet(socket_path, package, len);

	free(package);
	return err;
}

static int send_mode(const char *socket_path, spfs_mode_t mode, const char *path_to_send)
{
	size_t len;
	struct external_cmd *package;
	int err;

	printf("changing mode to %d (path: %s)\n", mode, path_to_send ? : "none");
	len = mode_packet_size(path_to_send);

	package = malloc(len);
	if (!package) {
		printf("failed to allocate package\n");
		return -ENOMEM;
	}
	fill_mode_packet(package, mode, path_to_send);

	err = send_packet(socket_path, package, len);

	free(package);
	return err;
}

static void help(char *program)
{
	printf("usage: %s command [options|payload]\n", program);
	printf("\n");
	printf("commands:\n");
	printf("\tmode                   allows to change mode work mode.\n");
	printf("\treplace                allows to request for spfs replacement.\n");
	printf("\tmanage                 send request to spfs manager\n");
	printf("\n");
	printf("general options:\n");
	printf("\t-s   --socket-path     control socket bind path\n");
	printf("\t-h   --help            print help (for double option will print fuse help)\n");
	printf("\n");
	printf("Mode options:\n");
	printf("\t--mode                 mode string (\"proxy\", \"stub\", or \"golem\")\n");
	printf("\t--path_to_send         proxy directory path to send to spfs\n");
	printf("\n");
	printf("Mount options:\n");
	printf("\t--source               file system fype source (default: \"none\")\n");
	printf("\t--fstype               file system fype (string)\n");
	printf("\t--mountflags           file system mount flags (default: 0)\n");
	printf("\t--options              file system mount options (default: empty)\n");
}

static int execude_mount_cmd(int argc, char **argv)
{
	long mountflags = 0;
	char *source = "none";
	char *type = NULL;
	char *options = NULL;
	char *socket_path = NULL;
	static struct option opts[] = {
		{"source",		required_argument,	0,	's' },
		{"mountflags",		required_argument,	0,	'f' },
		{"fstype",		required_argument,	0,	't' },
		{"options",		required_argument,	0,	'o' },
		{"socket-path",		required_argument,	0,	1003 },
		{"help",		no_argument,		0,	'h'},
		{0,			0,			0,	0 }
	};

	while (1) {
		int c;

		c = getopt_long(argc, argv, "f:t:o:h", opts, NULL);
		if (c == -1)
			break;

		switch (c) {
			case 'f':
				if (xatol(optarg, &mountflags))
					printf("mountflags is not a number: %s\n", optarg);
				break;
			case 't':
				type = optarg;
				break;
			case 's':
				source = optarg;
				break;
			case 'o':
				options = optarg;
				break;
			case 1003:
				socket_path = optarg;
				break;
			case 'h':
				help(argv[0]);
				return 0;
			case '?':
				help(argv[0]);
				return 1;
		}
	}

	if (!type) {
		printf("File system type wasn't provided\n");
		help(argv[0]);
		return 1;
	}

	if (!socket_path) {
		printf("Socket path wasn't provided\n");
		help(argv[0]);
		return 1;
	}

	return send_mount(socket_path, source, type, mountflags, options);
}

static int execude_manage_cmd(int argc, char **argv)
{
	char *payload = NULL;
	char *socket_path = NULL;
	static struct option opts[] = {
		{"socket-path",		required_argument,	0,	1003 },
		{"help",		no_argument,		0,	'h'},
		{0,			0,			0,	0 }
	};

	while (1) {
		int c;

		c = getopt_long(argc, argv, "f:t:o:h", opts, NULL);
		if (c == -1)
			break;

		switch (c) {
			case 1003:
				socket_path = optarg;
				break;
			case 'h':
				help(argv[0]);
				return 0;
			case '?':
				help(argv[0]);
				return 1;
		}
	}

	if (!socket_path) {
		printf("Socket path wasn't provided\n");
		help(argv[0]);
		return 1;
	}

	if (optind >= argc) {
		printf("Expected argument after options\n");
		help(argv[0]);
		return 1;
	}

	payload = argv[optind];

	printf("sending: '%s'\n", payload);

	return send_packet(socket_path, payload, strlen(payload) + 1);
}

static int execude_mode_cmd(int argc, char **argv)
{
	char *mode = NULL;
	char *socket_path = NULL;
	char *path_to_send = NULL;
	static struct option opts[] = {
		{"mode",		required_argument,	0,	1001 },
		{"path_to_send",	required_argument,	0,	1002 },
		{"socket-path",		required_argument,	0,	1003 },
		{"help",		no_argument,		0,	'h'},
		{0,			0,			0,	0 }
	};
	spfs_mode_t m;

	while (1) {
		int c;

		c = getopt_long(argc, argv, "h", opts, NULL);
		if (c == -1)
			break;

		switch (c) {
			case 1001:
				mode = optarg;
				break;
			case 1002:
				path_to_send = optarg;
				break;
			case 1003:
				socket_path = optarg;
				break;
			case 'h':
				help(argv[0]);
				return 0;
			case '?':
				printf("unknown option: %s\n", argv[optind]);
				help(argv[0]);
				return 1;
		}
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

	m = spfs_mode(mode, path_to_send);
	if (m < 0) {
		help(argv[0]);
		return 1;
	}
	return send_mode(socket_path, m, path_to_send);
}

int main(int argc, char **argv)
{
	int err;

	if (argc < 2) {
		help(argv[0]);
		return 1;
	}
	if (!strcmp(argv[1], "mode"))
		err = execude_mode_cmd(argc-1, argv+1);
	else if (!strcmp(argv[1], "mount"))
		err = execude_mount_cmd(argc-1, argv+1);
	else if (!strcmp(argv[1], "manage"))
		err = execude_manage_cmd(argc-1, argv+1);
	else {
		printf("Unknown command: %s\n", argv[1]);
		help(argv[0]);
		return 1;
	}
	if (err)
		printf("failed with error %d\n", err);
	return err;
}
