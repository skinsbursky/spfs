#ifndef __SPFS_MANAGER_CONTEXT_H_
#define __SPFS_MANAGER_CONTEXT_H_

#include <stdbool.h>

#include "include/namespaces.h"

struct spfs_manager_context_s {
	const char	*progname;

	char	*work_dir;
	char	*log_file;
	char	*socket_path;
	int	verbosity;
	bool	daemonize;
	bool	exit_with_spfs;
	char	*ovz_id;

	int	sock;

	int	ns_fds[NS_MAX];

	struct shared_list *spfs_mounts;
	struct shared_list *freeze_cgroups;
};

struct spfs_manager_context_s *create_context(int argc, char **argv);

extern int spfs_manager_packet_handler(int sock, void *data, void *package, size_t psize);

int join_namespaces(int pid, const char *namespaces);
int join_one_namespace(int pid, const char *ns);

#endif
