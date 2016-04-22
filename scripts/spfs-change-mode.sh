#!/bin/bash

[[ "post-restore" == "$CRTOOLS_SCRIPT_ACTION" ]] || exit 0

set -o pipefail

[ -n $SPFS_MANAGER_SOCK ] || exit 0
[ -n $SPFS_MODE ] || exit 0

[ -S $SPFS_MANAGER_SOCK ] || exit 1

SPFS_CLIENT="/usr/sbin/spfs-client"
[ -x "$SPFS_CLIENT" ] || exit 2

$SPFS_CLIENT manage "mode;all;mode=$SPFS_MODE" --socket-path $SPFS_MANAGER_SOCK > /dev/null
exit $?
