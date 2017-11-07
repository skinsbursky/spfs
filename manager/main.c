#include "spfs_config.h"

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>

#include "include/socket.h"
#include "include/log.h"

#include "context.h"
#include "interface.h"
#include "cgroup.h"

int main(int argc, char *argv[])
{
	struct spfs_manager_context_s *ctx;

	ctx = create_context(argc, argv);
	if (!ctx)
		return -1;

	if (mgr_ovz_id()) {
		pr_info("Move itself to VE#%s\n", mgr_ovz_id());
		if (move_to_cgroup("ve/", mgr_ovz_id()))
			return -1;
		pr_info("Move itself to freezer root cgroup\n");
		if (move_to_cgroup("freezer", "/"))
			return -1;
	}

	if (ctx->daemonize) {
		if (daemon(1, 1)) {
			pr_perror("failed to daemonize");
			return -errno;
		}
	}

	return unreliable_socket_loop(ctx->sock, ctx, false, spfs_manager_packet_handler);
}
