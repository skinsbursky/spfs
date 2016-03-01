#!/bin/bash

[[ "post-restore" == "$CRTOOLS_SCRIPT_ACTION" ]] || exit 0

[ -z "$FUSE_CLIENT" ] && exit 1
[ -z "$FUSE_DIR_PATTERN" ] && exit 2
[ -z "$FUSE_MODE" ] && exit 3

set -o pipefail

for sock in $FUSE_DIR_PATTERN*/*.sock; do
	$FUSE_CLIENT mode --mode $FUSE_MODE --socket_path $sock
	[ $? -eq 0 ] || exit 4
done

exit 0
