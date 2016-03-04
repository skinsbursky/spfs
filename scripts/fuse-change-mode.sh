#!/bin/bash

[[ "post-restore" == "$CRTOOLS_SCRIPT_ACTION" ]] || exit 0

[ -n "$FUSE_DIR_PATTERN" ] || exit 0
[ -n "$FUSE_CLIENT" ] || exit 1
[ -n "$FUSE_MODE" ] || exit 2

set -o pipefail

for sock in $FUSE_DIR_PATTERN*/*.sock; do
	$FUSE_CLIENT mode --mode $FUSE_MODE --socket_path $sock
	[ $? -eq 0 ] || exit 3
done

exit 0
