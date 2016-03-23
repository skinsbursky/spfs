#ifndef __SPFS_SOCKET_H_
#define __SPFS_SOCKET_H_

#include <stdbool.h>

struct sockaddr_un;
int seqpacket_sock(const char *path, bool save_fd, bool start_listen,
		   struct sockaddr_un *address);
int send_packet(const char *socket_path, void *package, size_t psize);

int reliable_socket_loop(int psock, void *data,
			 int (*packet_handler)(void *data, void *packet, size_t psize));
int socket_loop(int psock, void *data, int (*handler)(int sock, void *data));

#endif
