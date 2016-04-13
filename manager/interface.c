#include <stdlib.h>

#include "include/socket.h"

#include "include/log.h"
#include "include/util.h"

#include "spfs/interface.h"

#include "context.h"
#include "interface.h"
#include "mount.h"

int spfs_manager_packet_handler(int sock, void *data, void *package, size_t psize)
{
	struct spfs_manager_context_s *ctx = data;
	struct external_cmd *order;

	order = (struct external_cmd *)package;
	pr_debug("%s: cmd: %d\n", __func__, order->cmd);
	switch (order->cmd) {
		case SPFS_CMD_SET_MODE:
		case SPFS_MANAGER_MOUNT_FS:
			return mount_fs(sock, ctx, order->ctx, psize);
		default:
			pr_err("%s: unknown cmd: %d\n", __func__, order->cmd);
			return -1;
	}
	return 0;
}
