#include <stdlib.h>

#include "include/socket.h"

#include "include/log.h"
#include "include/util.h"

#include "spfs/interface.h"

#include "context.h"
#include "interface.h"

static int send_packet_to_spfs(struct spfs_manager_context_s *ctx,
				void *package, size_t psize)
{
	char *socket_path;
	int err;

	socket_path = xsprintf("%s/spfs.sock", ctx->work_dir);
	if (!socket_path)
		return -ENOMEM;

	err = send_packet(socket_path, package, psize);

	free(socket_path);
	return err;

}

int spfs_manager_packet_handler(void *data, void *package, size_t psize)
{
	struct spfs_manager_context_s *ctx = data;
	struct external_cmd *order;

	order = (struct external_cmd *)package;
	pr_debug("%s: cmd: %d\n", __func__, order->cmd);
	switch (order->cmd) {
		case SPFS_CMD_SET_MODE:
		case SPFS_CMD_INSTALL_PATH:
			return send_packet_to_spfs(ctx, package, psize);
		default:
			pr_err("%s: unknown cmd: %d\n", __func__, order->cmd);
			return -1;
	}
	return 0;
}
