#include "spfs_config.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#include "include/util.h"
#include "include/log.h"
#include "include/socket.h"

int seqpacket_sock_send(int sock, void *packet, size_t psize)
{
	ssize_t bytes;
	int err;

	bytes = send(sock, packet, psize, MSG_EOR);
	if (bytes < 0) {
		pr_perror("failed to send packet via sock %d", sock);
		return -errno;
	}

	bytes = recv(sock, &err, sizeof(err), 0);
	if (bytes < 0) {
		pr_perror("failed to receive reply via sock %d", sock);
		return -errno;
	}

	return err;
}

int send_packet(const char *socket_path, void *package, size_t psize)
{
	int sock, err;

	sock = seqpacket_sock(socket_path, false, false, NULL);
	if (sock < 0)
		return sock;

	err = seqpacket_sock_send(sock, package, psize);

	close(sock);
	return err;
}

int send_status(int sock, int res)
{
	ssize_t bytes;

	bytes = send(sock, &res, sizeof(res), MSG_NOSIGNAL | MSG_DONTWAIT | MSG_EOR);
	if (bytes < 0) {
		pr_perror("%s: send failed via fd %d", __func__, sock);
		return -errno;
	}

	if (bytes == 0) {
		pr_info("%s: peer was closed for fd %d\n", __func__, sock);
		return -ECONNABORTED;
	}
	return 0;
}

int reliable_conn_handler(int sock, void *data,
			  int (*packet_handler)(int sock, void *data, void *packet, size_t psize))
{
	char page[4096];
	ssize_t bytes;

	bytes = recv(sock, page, sizeof(page), 0);
	if (bytes < 0) {
		pr_perror("%s: recv failed", __func__);
		return -errno;
	}
	if (bytes == 0) {
		pr_debug("%s: peer was closed\n", __func__);
		return -ECONNABORTED;
	}

	pr_debug("received %ld bytes\n", bytes);

	return send_status(sock, packet_handler(sock, data, page, bytes));
}

int reliable_socket_loop(int psock, void *data, bool async,
			 int (*packet_handler)(int sock, void *data, void *packet, size_t psize))
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

		if (async) {
			int pid;

			pid = fork();
			switch (pid) {
				case -1:
					pr_err("failed to fork\n");
					break;
				case 0:
					close(psock);
					_exit(reliable_conn_handler(sock, data, packet_handler));
			}
		} else
			(void) reliable_conn_handler(sock, data, packet_handler);

		close(sock);
	}
	return 0;
}

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

int seqpacket_sock(const char *path, bool move_fd, bool start_listen,
		     struct sockaddr_un *address)
{
	int err, sock;
	struct sockaddr_un addr;

	pr_debug("creating SOCK_SEQPACKET socket: %s\n", path);
	sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sock < 0) {
		pr_perror("failed to create socket");
		return -errno;
	}

	if (move_fd) {
		sock = save_fd(sock, O_CLOEXEC);
		if (sock < 0) {
			pr_crit("failed to save sock fd\n");
			return sock;
		}
		pr_debug("Socket was moved to fd: %d\n", sock);
	}

	memset(&addr, 0, sizeof(addr.sun_path));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (start_listen) {
		if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
			pr_perror("failed to bind socket to %s", addr.sun_path);
			goto err;
		}

		if (listen(sock, 20) == -1) {
			pr_perror("failed to start listen to socket %s",
					addr.sun_path);
			goto err;
		}
		pr_info("listening to %s\n", addr.sun_path);
	} else {
		if (connect(sock, (struct sockaddr *)&addr, sizeof(addr))) {
			pr_perror("failed to connect to socket %s", addr.sun_path);
			goto err;
		}
		pr_info("connected to %s\n", addr.sun_path);
	}

	if (address)
		*address = addr;

	return sock;

err:
	err = -errno;
	close(sock);
	return err;
}
