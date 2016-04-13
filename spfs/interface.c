#include "spfs_config.h"

#include "include/util.h"
#include "include/log.h"

#include "context.h"
#include "interface.h"

int spfs_execute_cmd(int sock, void *data, void *package, size_t psize)
{
	struct spfs_context_s *ctx = data;
	struct external_cmd *order;
	struct cmd_package_s *mp;

	order = (struct external_cmd *)package;
	pr_debug("%s: cmd: %d\n", __func__, order->cmd);
	switch (order->cmd) {
		case SPFS_CMD_SET_MODE:
			mp = (struct cmd_package_s *)order->ctx;
			return change_work_mode(ctx, mp->mode, mp->path);
		default:
			pr_err("%s: unknown cmd: %d\n", __func__, order->cmd);
			return -1;
	}
	return 0;
}
