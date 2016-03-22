#include "spfs_config.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "include/util.h"
#include "include/log.h"
#include "include/socket.h"

int socket_loop(int psock, void *data, int (*handler)(int sock, void *data))
{
	pr_info("%s: socket loop started\n", __func__);

	while(1) {
		int sock;

		sock = accept(psock, NULL, NULL);
		if (sock < 0) {
			pr_perror("%s: accept failed", __func__);
			break;
		}

		pr_debug("%s: accepted new socket\n", __func__);
		(void) handler(sock, data);

		close(sock);
	}
	return 0;
}

int sock_seqpacket(const char *path, bool move_fd, bool start_listen,
		     struct sockaddr_un *address)
{
	int err, sock;
	struct sockaddr_un addr;

	pr_debug("creating SOCK_SEQPACKET socket: %s\n", path);
	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock < 0) {
		pr_perror("failed to create socket");
		return -errno;
	}

	pr_debug("socket fd: %d\n", sock);

	if (move_fd) {
		sock = save_fd(sock);
		if (sock < 0) {
			pr_crit("failed to save sock fd\n");
			return sock;
		}
		pr_debug("Socket was moved to fd: %d\n", sock);
	}

#if 0
	if (!access(path, F_OK) && (unlink(path) < 0)) {
		err = -errno;
		pr_crit("fuse: failed to unlink %s: %d\n", path, -errno);
		return err;
	}
#endif

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	err = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (err) {
		pr_perror("failed to bind socket to %s", addr.sun_path);
		goto err;
	}

	if (start_listen) {
		if (listen(sock, 20) == -1) {
			pr_perror("failed to start listen to socket %s",
					addr.sun_path);
			goto err;
		}
	}

	if (address)
		*address = addr;

	pr_info("listening to %s\n", addr.sun_path);
	return 0;

err:
	err = -errno;
	close(sock);
	return err;
}
