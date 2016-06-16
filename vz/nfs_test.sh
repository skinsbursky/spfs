#!/bin/bash
CTID=$1
ZDTM_DIR=$2

#STATIC_TEST_LIST="fifo_wronly fifo fifo_ro fifo-rowo-pair chroot fd fdt_shared \
#		  file_append file_fown file_shared maps00 \
#		  maps_file_prot write_read00 write_read01 write_read02 \
#		  deleted_unix_sock sk-unix-unconn"

STATIC_TEST_LIST="	\
		write_read00		\
		write_read01		\
		write_read02		\
		file_fown		\
		file_locks00		\
		file_locks02		\
		file_locks03		\
		file_locks04		\
		file_locks05		\
		file_shared		\
		file_append		\
		socket_queues		\
		socket-ext		\
		sockets_dgram		\
		socket_dgram_data		\
		deleted_unix_sock		\
		pipe02		\
		fdt_shared		\
		maps00		\
		maps02		\
		maps05		\
		maps_file_prot		\
		mtime_mmap		\
		fifo		\
		fifo_ro		\
		fifo_wronly		\
		fifo-rowo-pair		\
		sk-unix-unconn		\
		inotify_irmap		\
		fd		\
		cwd00		\
		selfexe00		\
		mprotect00		\
		chroot		\
		chroot-file		\
		"

STATIC_NOT_STARTING_TEST_LIST="		\
		deleted_dev		\
		fanotify00		\
		unlink_fstat00		\
		maps04		\
		maps03		\
		sockets00		\
		vt		\
		"

STATIC_NOT_DUMPABLE_OVERMOUNT_TEST_LIST="			\
		bind-mount		\
		tempfs		\
		"
STATIC_NOT_DUMPABLE_STALE_TEST_LIST="			\
		rmdir_open		\
		cwd01		\
		cwd02		\
		"

STATIC_NOT_DUMPABLE_UNLINKED_TEST_LIST="			\
		unlink_fstat01		\
		unlink_fstat02		\
		unlink_fstat03		\
		unlink_mmap01		\
		unlink_mmap02		\
		unlink_mmap00		\
		link10		\
		unlink_fifo		\
		unlink_fifo_wronly		\
		write_read10		\
		file_attr		\
		fifo-ghost		\
		"

STATIC_NOT_DUMPABLE_SOCKETS_TEST_LIST="			\
		sk-unix-rel		\
		"
STATIC_ALWAYS_FAIL_TEST_LIST="			\
		file_locks01		\
		"

#STREAMING_TEST_LIST="fifo_dyn fifo_loop"
#STREAMING_TEST_LIST="fifo_dyn"
#STREAMING_TEST_LIST=""

#TRANSITION_TEST_LIST="file_read"
#TRANSITION_TEST_LIST=""

TESTS_LIST="$STATIC_TEST_LIST $STREAMING_TEST_LIST $TRANSITION_TEST_LIST"

static_test_dir=""
transition_test_dir=""

function vz_ct_exec {
	local cmd=$1

#	echo "vz_ct_exec: $cmd"
	$(vzctl exec $CTID $cmd > /dev/null)
}


#vz_ct_exec "test -d $ZDTM_DIR/live"

#if [ $? -eq 0 ]; then
#	static_test_dir="${ZDTM_DIR}/live/static"
#	streaming_test_dir="${ZDTM_DIR}/live/streaming"
#	transition_test_dir="${ZDTM_DIR}/live/transition"
#else
	static_test_dir="${ZDTM_DIR}/static"
	streaming_test_dir="${ZDTM_DIR}/transition"
	transition_test_dir="${ZDTM_DIR}/transition"
#fi

vz_ct_exec "test -d $static_test_dir"
if [ $? -ne 0 ]; then
	echo "failed to find static tests in $ZDTM_DIR"
	return 1
fi

vz_ct_exec "test -d $streaming_test_dir"
if [ $? -ne 0 ]; then
	echo "failed to find streaming tests in $ZDTM_DIR"
	return 1
fi


vz_ct_exec "test -d $transition_test_dir"
if [ $? -ne 0 ]; then
	echo "failed to find transition tests in $ZDTM_DIR"
	return 1
fi

printf_test_len=0

PASSED_TESTS=""
FAILED_TESTS=""

function test_file_exist {
	local test_dir=$1
	local test_name=$2
	local file=$3

	vz_ct_exec "test -f $test_dir/${test_name}.${file}"
}

function cat_test_file {
	local test_dir=$1
	local test_name=$2
	local file=$3

	echo $(vzctl exec $CTID cat $test_dir/${test_name}.${file})
}

function test_operation {
	local test_dir=$1
	local test_name=$2
	local op=$3

	vz_ct_exec "make -C $test_dir ${test_name}.${op}"
}

function start_one_test {
	local test_dir=$1
	local test_name=$2

	test_operation $test_dir $test_name "pid"
}

function stop_one_test {
	local test_dir=$1
	local test_name=$2

	test_operation $test_dir $test_name "out"
}

function start_tests {
	local test_dir=$1
	local list=$2

	vz_ct_exec "make -C $test_dir cleanout"

	for t in $list; do
		start_one_test $test_dir $t
		if [ $? -ne 0 ]; then
			echo "failed to start $test_dir/$test_name"
			echo $(cat_test_file $test_dir $t "out")
			return 1
		fi
		local pid=$(cat_test_file $test_dir $t "pid")
		printf "\t%-*s: %s\n" $printf_test_len "$t" "$pid"
	done
}

function test_result {
	local test_dir=$1
	local t=$2

	while true; do
		vz_ct_exec "test -f $test_dir/${t}.out" && break
	done
	out_file=$(cat_test_file $test_dir $t "out")
	if [ -n "$(echo $out_file | grep 'PASS')" ]; then
		echo "PASS"
	else
		echo "FAIL"
	fi
}

function stop_tests {
	local test_dir=$1
	local list=$2

	for t in $list; do
		stop_one_test $test_dir $t
		local out=$(test_result $test_dir $t "out")
		printf "\t%-*s: %s\n" $printf_test_len "$t" "$out"
		if [ "$out" == "PASS" ]; then
			PASSED_TESTS="$PASSED_TESTS $t"
		else
			FAILED_TESTS="$FAILED_TESTS $t"
		fi
	done
}

function kill_tests {
	local list=$1

	echo "Killing tests"

	for t in $list; do
		killall -9 $t > /dev/null 2>&1
	done
}

function get_spfs_processes_list {
#	echo $(ps axf  | grep " [s]pfs\|[spfs]w-manager ")
	echo $(ps axf  | grep " [s]pfs\ ")
}

function wait_spfs_exited {
	local list=$(get_spfs_processes_list)
	local attempts=0

	echo "Waiting until SPFS is exited..."

	while [ -n "$list" ]; do
		attempts=$((attempts + 1))
		if [ $attempts -eq 5 ]; then
			return 1
		fi
		sleep 1
		list=$(get_spfs_processes_list)
	done
	return 0
}

function suspend_restore {
	local ID=$1

	echo "Suspending $ID"
	vzctl suspend $ID > /dev/null 2>&1
	if [ $? -ne 0 ]; then 
		echo "failed to suspend"
		return 1
	fi

	echo "Restoring $ID"
	vzctl restore $ID > /dev/null 2>&1
	if [ $? -ne 0 ]; then 
		echo "failed to resume"
		exit 1
	fi

	wait_spfs_exited
	if [ $? -ne 0 ]; then 
		echo "failed to wait till SPFS is exited"
		exit 1
	fi

#	check_zombies
#	if [ $? -ne 0 ]; then 
#		echo "Found zombies"
#		return 1
#	fi
#	echo "Processes are ok"
}


function set_test_print_len {
	local list=$1
	local max_len=0
	local tests_nr=0

	for t in $list; do
		local len=${#t} 
		if [ $len -gt $max_len ]; then
			max_len=$len;
		fi
		tests_nr=$((tests_nr + 1))
	done
	echo "Number of tests: $tests_nr"
	printf_test_len=$max_len
}

set_test_print_len "$TESTS_LIST"

kill_tests "$TESTS_LIST"

echo "Start tests"
start_tests $static_test_dir "$STATIC_TEST_LIST"
if [ $? -ne 0 ]; then
	kill_tests "$TESTS_LIST"
	exit 1
fi

start_tests $streaming_test_dir "$STREAMING_TEST_LIST"
if [ $? -ne 0 ]; then
	kill_tests "$TESTS_LIST"
	exit 1
fi

start_tests $transition_test_dir "$TRANSITION_TEST_LIST"
if [ $? -ne 0 ]; then
	kill_tests "$TESTS_LIST"
	exit 1
fi

suspend_restore $CTID || exit 1

echo "Stop tests"
stop_tests $transition_test_dir "$TRANSITION_TEST_LIST"
stop_tests $streaming_test_dir "$STREAMING_TEST_LIST"
stop_tests $static_test_dir "$STATIC_TEST_LIST"

if [ -n "$FAILED_TESTS" ]; then
	echo "Failed tests"
	for t in $FAILED_TESTS; do
		printf "\t%-*s: FAIL\n" $printf_test_len "$t"
	done
fi
