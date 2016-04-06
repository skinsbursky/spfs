#ifndef __SPFS_MANAGER_CONTEXT_H_
#define __SPFS_MANAGER_CONTEXT_H_

#include <stdbool.h>
#include <stddef.h>

#include <spfs/context.h>

struct spfs_manager_context_s {
	const char	*progname;

	char	*start_mode;
	char	*work_dir;
	char	*spfs_dir;
	char	*log_file;
	char	*spfs_root;
	char	*socket_path;
	int	verbosity;
	bool	daemonize;
	char	*process_id;
	char	*namespaces;
	char	*cgroups;
	char	*proxy_dir;
	char	*mountpoint;

	spfs_mode_t mode;
	long	ns_pid;

	int	sock;

	char	*spfs_socket;
};

struct spfs_manager_context_s *create_context(int argc, char **argv);

extern int spfs_manager_packet_handler(void *data, void *package, size_t psize);

int join_namespaces(int pid, const char *namespaces);

#endif
