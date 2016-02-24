#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "interface.h"
#include "util.h"

static int send_data(int sock, void *ctx, size_t len)
{
	ssize_t bytes;

	bytes = send(sock, ctx, len, MSG_EOR);
	if (bytes < 0) {
		printf("failed to send package %d\n", -errno);
		return -1;
	}
	return 0;
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

int main(int argc, char **argv)
{
	int sock, err;
	struct sockaddr_un addr;

	if (argc < 2) {
		printf("Usage: fuse_client <path_to_send> <path_to_stat>\n");
		printf("       fuse_client <mode>\n");
		return -1;
	}

	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock < 0) {
		printf("Failed to create packet socket\n");
		return -1;
	}
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
//	strncpy(addr.sun_path, "/var/run/fuse_stub_proxy.sock",
//	strncpy(addr.sun_path, "/fuse_stub_proxy.sock",
//	strncpy(addr.sun_path, "/vz/root/102/fuse_stub_proxy.sock",
	strncpy(addr.sun_path, "/var/run/fuse_control.sock",
			sizeof(addr.sun_path) - 1);

	err = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (err) {
		printf("failed to connect socket to %s\n", addr.sun_path);
		return -1;
	}

	if (atoi(argv[1]) == FUSE_CMD_SET_MODE)
		return send_mode(sock, atoi(argv[2]));
	else if (atoi(argv[1]) == FUSE_CMD_INSTALL_PATH)
		return send_path(sock, argv[2], argv[3]);
	printf("Unknown command: %s\n", argv[1]);
	return -EINVAL;
}
