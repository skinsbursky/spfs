#ifndef __SPFS_MANAGER_CONTEXT_H_
#define __SPFS_MANAGER_CONTEXT_H_

#include <stdbool.h>

struct spfs_manager_context_s {
	char	*work_dir;
	char	*log_file;
	char	*socket_path;
	int	verbosity;
	bool	daemonize;
	char	*process_id;
	char	*namespaces;
	char	*cgroups;
	char	*mountpoint;

	int	sock;
};

struct spfs_manager_context_s *create_context(int argc, char **argv);

#endif
