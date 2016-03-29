#include <errno.h>
#include <getopt.h>
#include <stdio.h>

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

	printf("mounting %s with flags %ld and options '%s'\n", type,
			mountflags, options);

	len = mount_packet_size(source, type, options);

	package = malloc(len);
	if (!package) {
		printf("failed to allocate package\n");
		return -ENOMEM;
	}
	fill_mount_packet(package, source, type, options, mountflags);

	return send_packet(socket_path, package, len);
}

static int send_path(const char *socket_path, const char *path_to_send, const char *path_to_stat)
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

	return send_packet(socket_path, package, len);
}

static int send_mode(const char *socket_path, int mode, const char *path_to_send)
{
	size_t len;
	struct external_cmd *package;

	printf("changind mode to %d (path: %s)\n", mode, path_to_send ? : "none");
	len = mode_packet_size(path_to_send);

	package = malloc(len);
	if (!package) {
		printf("failed to allocate package\n");
		return -ENOMEM;
	}
	fill_mode_packet(package, mode, path_to_send);

	return send_packet(socket_path, package, len);
}

static void help(char *program)
{
	printf("usage: %s command options\n", program);
	printf("\n");
	printf("commands:\n");
	printf("\tmode            allows to change mode work mode.\n");
	printf("\tpath            allows to send a path to be used in Golem mode.\n");
	printf("\tmount           allows to request for mount a filesystem.\n");
	printf("\n");
	printf("general options:\n");
	printf("\t-s   --socket_path     control socket bind path\n");
	printf("\t-h   --help            print help (for double option will print fuse help)\n");
	printf("\n");
	printf("Mode options:\n");
	printf("\t--mode            mode string (\"proxy\", \"stub\", or \"golem\")\n");
	printf("\t--path_to_send    proxy directory path to send to spfs\n");
	printf("\n");
	printf("Path options:\n");
	printf("\t--path_to_send    file path to send to spfs\n");
	printf("\t--path_to_stat    file path to stat\n");
	printf("\n");
	printf("Mount options:\n");
	printf("\t--source          fileystem fype source (default: \"none\"\n");
	printf("\t--fstype          fileystem fype (string)\n");
	printf("\t--mountflags      file system mount flags (default: 0)\n");
	printf("\t--options         file system mount options (default: empty)\n");
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
		{"socket_path",		required_argument,	0,	3 },
		{"help",		no_argument,		0,	'h'},
		{0,			0,			0,	0 }
	};

	while (1) {
		char c;

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
			case 3:
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
		}
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

	if (!socket_path) {
		printf("Socket path wasn't provided\n");
		help(argv[0]);
		return 1;
	}

	return send_path(socket_path, path_to_send, path_to_stat);
}

static int check_mode(const char *mode, const char *path_to_send)
{
	if (!strcmp(mode, "stub"))
		return SPFS_STUB_MODE;
	if (!strcmp(mode, "golem"))
		return SPFS_GOLEM_MODE;
	if (!strcmp(mode, "proxy")) {
		if (!path_to_send) {
			printf("Proxy directory path wasn't provided\n");
			return -EINVAL;
		}
		if (!strlen(path_to_send)) {
			printf("Proxy directory path is empty\n");
			return -EINVAL;
		}
		return SPFS_PROXY_MODE;
	}
	printf("Unknown mode: %s\n", mode);
	return -EINVAL;
}

static int execude_mode_cmd(int argc, char **argv)
{
	char *mode = NULL;
	char *socket_path = NULL;
	char *path_to_send = NULL;
	static struct option opts[] = {
		{"mode",		required_argument,	0,	1 },
		{"path_to_send",	required_argument,	0,	2 },
		{"socket_path",		required_argument,	0,	3 },
		{"help",		no_argument,		0,	'h'},
		{0,			0,			0,	0 }
	};
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
				path_to_send = optarg;
				break;
			case 3:
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
#if 0
	if (xatol(mode, &m)) {
#else
	m = check_mode(mode, path_to_send);
	if (m < 0) {
#endif
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
		err = execude_mode_cmd(argc, argv);
	else if (!strcmp(argv[1], "path"))
		err = execude_path_cmd(argc, argv);
	else if (!strcmp(argv[1], "mount"))
		err = execude_mount_cmd(argc, argv);
	else {
		printf("Unknown command: %s\n", argv[1]);
		help(argv[0]);
		return 1;
	}
	if (err)
		printf("failed with error %d\n", err);
	return err;
}
