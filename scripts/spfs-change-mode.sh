#!/bin/bash

[[ "post-restore" == "$CRTOOLS_SCRIPT_ACTION" ]] || exit 0

SPFS_CLIENT="/usr/sbin/spfs-client"
[ -x "$SPFS_CLIENT" ] || exit 1
[ -S $SPFS_MANAGER_SOCK ] || exit 2

set -o pipefail

echo "$SPFS_CLIENT manage 'mode;all;mode=stub' --socket-path $SPFS_MANAGER_SOCK"
$SPFS_CLIENT manage 'mode;all;mode=stub' --socket-path $SPFS_MANAGER_SOCK
exit $?
