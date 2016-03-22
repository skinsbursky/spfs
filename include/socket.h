#ifndef __SPFS_SOCKET_H_
#define __SPFS_SOCKET_H_

#include <stdbool.h>

struct sockaddr_un;
int sock_seqpacket(const char *path, bool save_fd, bool start_listen,
		   struct sockaddr_un *address);


int socket_loop(int psock, void *data, int (*handler)(int sock, void *data));

#endif
