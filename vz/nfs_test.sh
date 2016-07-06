#!/bin/bash

TESTS_LIST="	\
		static/write_read00		\
		static/write_read01		\
		static/write_read02		\
		static/file_fown		\
		static/file_locks00		\
		static/file_locks02		\
		static/file_locks03		\
		static/file_locks04		\
		static/file_locks05		\
		static/file_shared		\
		static/file_append		\
		static/socket_queues		\
		static/socket-ext		\
		static/sockets_dgram		\
		static/socket_dgram_data	\
		static/deleted_unix_sock	\
		static/pipe02			\
		static/fdt_shared		\
		static/maps00			\
		static/maps02			\
		static/maps05			\
		static/maps_file_prot		\
		static/mtime_mmap		\
		static/fifo			\
		static/fifo_ro			\
		static/fifo_wronly		\
		static/fifo-rowo-pair		\
		static/sk-unix-unconn		\
		static/inotify_irmap		\
		static/fd			\
		static/cwd00			\
		static/selfexe00		\
		static/mprotect00		\
		static/chroot			\
		static/chroot-file		\
						\
		transition/fifo_loop		\
		transition/fifo_dyn		\
		transition/epoll		\
		transition/file_aio		\
		transition/file_read		\
		"

NOT_STARTING_TEST_LIST="			\
		static/deleted_dev		\
		static/fanotify00		\
		static/unlink_fstat00		\
		static/maps04			\
		static/maps03			\
		static/sockets00		\
		static/vt			\
		"

NOT_DUMPABLE_OVERMOUNT_TEST_LIST="		\
		static/bind-mount		\
		static/tempfs			\
		"
NOT_DUMPABLE_STALE_TEST_LIST="			\
		static/rmdir_open		\
		static/cwd02			\
		"

NOT_DUMPABLE_UNLINKED_TEST_LIST="		\
		static/cwd01			\
		static/unlink_fstat01		\
		static/unlink_fstat02		\
		static/unlink_fstat03		\
		static/unlink_mmap01		\
		static/unlink_mmap02		\
		static/unlink_mmap00		\
		static/link10			\
		static/unlink_fifo		\
		static/unlink_fifo_wronly	\
		static/write_read10		\
		static/file_attr		\
		static/fifo-ghost		\
		"

NOT_DUMPABLE_SOCKETS_TEST_LIST="		\
		static/sk-unix-rel		\
		"
ALWAYS_FAIL_TEST_LIST="				\
		static/file_locks01		\
		"
function vz_ct_exec {
	local cmd=$1

	echo $(vzctl exec $CTID $cmd)
}

function vz_ct_exec_silent {
	local cmd=$1

	$(vzctl exec $CTID $cmd > /dev/null)
}

printf_test_len=0

PASSED_TESTS=""
FAILED_TESTS=""

function test_file_exist {
	local test_dir=$1
	local test_name=$2
	local file=$3

	vz_ct_exec_silent "test -f $test_dir/${test_name}.${file}"
}

function cat_test_file {
	local test_dir=$1
	local test_name=$2
	local file=$3

	vz_ct_exec "cat $test_dir/${test_name}.${file}"
}

function test_operation {
	local test_dir=$1
	local test_name=$2
	local op=$3
	local array

	IFS='/' read -ra array <<< "$test_name"

	vz_ct_exec_silent "make -C $test_dir/${array[0]} ${array[1]}.${op}"
}

function get_test_pid {
	local test_dir=$1
	local test_name=$2
	local pid="0"

	test_file_exist $test_dir $t "pid"
	if [ $? -eq 0 ]; then
		pid="$(cat_test_file $test_dir $t "pid")"
	fi
	echo $pid
}

function test_is_running {
	local pid=$(get_test_pid $1 $2)
	local res=$(vz_ct_exec "ps axf | grep \"^ *$pid \" | awk '{print \$1;}'")
	echo $res
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

	running_tests=""

	for t in $list; do
		local pid="not found"

		printf "\t%-*s: " $printf_test_len "$t"
		test_file_exist $test_dir $t "c"
		if [ $? -eq 0 ]; then
			pid=$(test_is_running $test_dir $t)
			if [ -n "$pid" ]; then
				echo "already running"
				running_tests="$running_tests $t"
				continue
			fi

			test_file_exist $test_dir $t "pid" || 
			test_file_exist $test_dir $t "out" ||
			test_file_exist $test_dir $t "out.inprogress"
			if [ $? -eq 0 ]; then
				echo "dirty"
				return 1
			fi

			start_one_test $test_dir $t
			if [ $? -ne 0 ]; then
				echo "failed to start $test_dir/$test_name"
				echo $(cat_test_file $test_dir $t "out")
				return 1
			fi
			local pid=$(cat_test_file $test_dir $t "pid")
			running_tests="$running_tests $t"
		fi
		printf "%s\n" "$pid"
	done
}

function test_result {
	local test_dir=$1
	local t=$2
	local attempts=15

	while [ -n "$list" ]; do
		attempts=$((attempts - 1))
		if [ $attempts -eq 0 ]; then
			echo "no out file"
			return 1
		fi
		sleep 0.2
		vz_ct_exec_silent "test -f $test_dir/${t}.out" && break
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
	local array=($list)

	for (( idx=${#array[@]}-1 ; idx>=0 ; idx-- )) ; do
		local t=${array[idx]}
		printf "\t%-*s: " $printf_test_len "$t"

		pid=$(test_is_running $test_dir $t)
		if [ -n "$pid" ]; then
			stop_one_test $test_dir $t
			local out=$(test_result $test_dir $t "out")
			printf "%s\n" "$out"
			if [ "$out" == "PASS" ]; then
				PASSED_TESTS="$PASSED_TESTS $t"
			else
				FAILED_TESTS="$FAILED_TESTS $t"
			fi
		else
			printf "not running\n"
			SKIPPED_TESTS="$SKIPPED_TESTS $t"
		fi
	done
}

function kill_tests {
	local list=$1

	[ -n "$list" ] || return 0

	echo -n "Killing tests... "

	for t in $list; do
		IFS='/' read -ra array <<< "$t"
		killall -9 ${array[1]} > /dev/null 2>&1
	done
	echo "done"
}

function get_spfs_processes_list {
#	echo $(ps axf  | grep " [s]pfs\|[spfs]w-manager ")
	echo $(ps axf  | grep " [s]pfs\ ")
}

function wait_spfs_exited {
	local list=$(get_spfs_processes_list)
	local attempts=25

	echo -n "Waiting until SPFS is exited... "

	while [ -n "$list" ]; do
		attempts=$((attempts - 1))
		if [ $attempts -eq 0 ]; then
			echo "timed out"
			return 1
		fi
		sleep 0.2
		list=$(get_spfs_processes_list)
	done
	echo "done"
	return 0
}

function suspend_restore {
	echo -n "Suspending $CTID... "
	vzctl suspend $CTID > /dev/null 2>&1
	if [ $? -ne 0 ]; then 
		echo "failed"
		grep Error /vz/private/$CTID/dump/Dump.fail/dump.log 
		return 1
	fi
	echo "done"

	echo -n "Restoring $CTID... "
	vzctl restore $CTID > /dev/null 2>&1
	if [ $? -ne 0 ]; then 
		echo "failed"
		grep Error /vz/private/$CTID/dump/Dump/restore.log 
		exit 1
	fi
	echo "done"

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

function list_tests {
	echo "Tests list:"
	for t in $tests_list; do
		printf "\t%s\n" "$t"
	done
}

function print_help {
cat<<EOF
usage:
nfs_test.sh [command] [options]...

Commands:
	start		start tests
	stop		stop tests
	clean		clean tests output
	cr		suspend and restore container
	list		print tests list
	kill		kill tests
	run		do the whole test sequence: kill, clean, start, suspend, restore, stop (default)

Options:
	-C --ctid       container ID
	-d --zdtm-dir   path to ZDTM tests within container
	-t --test       test name
	-h --help	this help

Examples:
	Run tests, located in /mnt/criu/test/zdtm in CT 102:
		nfs_test.sh --ctid 102 --zdtm-dir /mnt/criu/test/zdtm

	Kill all tests:
		nfs_test.sh kill

	List all tests:
		nfs_test.sh list

	Start only "static/deleted_unix_sock" test located in /mnt/criu/test/zdtm in CT 102:
		nfs_test.sh --ctid 102 --zdtm-dir /mnt/criu/test/zdtm -t static/deleted_unix_sock start

EOF
exit
}

function set_env {
	if [ -z "$CTID" ]; then
		echo "CT ID must be provided"
		exit 1
	fi

	if [ -z "$ZDTM_DIR" ]; then
		echo "Path to ZDTM tests must be provided"
		exit 1
	fi

	set_test_print_len "$tests_list"
}

function start_zdtm_tests {
	echo "Start tests:"
	start_tests $ZDTM_DIR "$tests_list"
	if [ $? -ne 0 ]; then
		kill_tests "$running_tests"
		exit 1
	fi
}

function stop_zdtm_tests {
	[ -n "$running_tests" ] || return 0

	echo "Stop tests:"
	stop_tests $ZDTM_DIR "$running_tests"

	if [ -n "$SKIPPED_TESTS" ]; then
		echo "Skipped tests"
		for t in $SKIPPED_TESTS; do
			printf "\t%-*s: SKIP\n" $printf_test_len "$t"
		done
	fi

	if [ -n "$FAILED_TESTS" ]; then
		echo "Failed tests"
		for t in $FAILED_TESTS; do
			printf "\t%-*s: FAIL\n" $printf_test_len "$t"
		done
	else
		echo "Success"
	fi
}

function clean_tests_out {
	vz_ct_exec_silent "make -C $ZDTM_DIR cleanout"
	vz_ct_exec_silent "rm -rf $ZDTM_DIR/*/*.test*"
}

function run_zdtm_tests {
	kill_tests "$tests_list"
	clean_tests_out
	start_zdtm_tests
	suspend_restore || exit 1
	stop_zdtm_tests
}

[ -n "$*" ] || print_help

while [ "$*" ] ; do
	arg="$1"
	shift
	case $arg in
		-C|--ctid)
			CTID=$1
			shift
			;;
		-d|--zdtm-dir)
			ZDTM_DIR=$1
			shift
			;;
		-t|--test)
			tests_list="$tests_list $1"
			shift
			;;
		-h|--help)
			print_help
			shift
			;;
		run)
			cmd="run"
			shift
			;;
		cr)
			cmd="cr"
			shift
			;;
		start)
			cmd="start"
			shift
			;;
		stop)
			cmd="stop"
			shift
			;;
		kill)
			cmd="kill"
			shift
			;;
		clean)
			cmd="clean"
			shift
			;;
		list)
			cmd="list"
			shift
			;;
		*)
			echo "unknown $arg"
			exit 2
			;;
	esac
done

[ -n "$cmd" ] || cmd="run"
[ -n "$tests_list" ] || tests_list="$TESTS_LIST"

running_tests="$tests_list"

case $cmd in
	run)
		set_env
		run_zdtm_tests
		;;
	start)
		set_env
		start_zdtm_tests
		;;
	stop)
		set_env
		stop_zdtm_tests
		;;
	list)
		list_tests
		;;
	clean)
		set_env
		clean_tests_out
		;;
	cr)
		suspend_restore
		;;
	kill)
		kill_tests "$tests_list"
		;;
esac
