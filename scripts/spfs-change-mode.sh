#!/bin/bash

[[ "post-restore" == "$CRTOOLS_SCRIPT_ACTION" ]] || exit 0

SPFS_CLIENT="/usr/sbin/spfs-client"
[ -n "$SPFS_DIR_PATTERN" ] || exit 0
[ -x "$SPFS_CLIENT" ] || exit 1
[ -n "$SPFS_MODE" ] || exit 2

set -o pipefail

for sock in `ls $SPFS_DIR_PATTERN/spfs-manager.sock 2> /dev/null`; do
	echo "$SPFS_CLIENT mode --mode $SPFS_MODE --socket_path $sock"
	$SPFS_CLIENT mode --mode $SPFS_MODE --socket_path $sock
	[ $? -eq 0 ] || exit 3
done

exit 0
