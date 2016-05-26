## Process this file with automake to produce Makefile.in
CLEANFILES = `find . -name "*~"`

AM_CFLAGS = -Wall -Werror -ggdb -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
AM_MAKEFLAGS = --no-print-directory

sbin_PROGRAMS = bin/spfs bin/spfs-client bin/spfs-manager

noinst_PROGRAMS = bin/swapfd

bin_spfs_SOURCES =		spfs/main.c			\
				spfs/gateway.c			\
				spfs/proxy.c			\
				spfs/stub.c			\
				spfs/context.c			\
				spfs/interface.c		\
								\
				spfs/interface.h		\
				spfs/context.h			\
								\
				src/util.c			\
				src/log.c			\
				src/socket.c			\
				src/futex.c			\
								\
				include/log.h			\
				include/socket.h		\
				include/list.h			\
				include/util.h			\
				include/futex.h


bin_spfs_client_SOURCES =	client/main.c			\
								\
				src/socket.c			\
				src/log.c			\
				src/util.c			\
								\
				spfs/interface.h		\
				spfs/context.h			\
								\
				include/socket.h		\
				include/util.h


bin_spfs_manager_SOURCES =	manager/main.c			\
				manager/context.c		\
				manager/interface.c		\
				manager/replace.c		\
				manager/spfs.c			\
				manager/freeze.c		\
				manager/swapfd.c		\
				manager/swap.c			\
				manager/trees.c			\
				manager/processes.c		\
				manager/cgroup.c		\
				manager/mount.c			\
								\
				manager/context.h		\
				manager/interface.h		\
				manager/replace.h		\
				manager/spfs.h			\
				manager/freeze.h		\
				manager/swapfd.h		\
				manager/swap.h			\
				manager/trees.h			\
				manager/processes.h		\
				manager/cgroup.h		\
				manager/mount.h			\
								\
				src/util.c			\
				src/socket.c			\
				src/ipc.c			\
				src/log.c			\
				src/shm.c			\
				src/ptrace.c			\
				src/pie-util-fd.c		\
				src/futex.c			\
								\
				spfs/interface.h		\
				spfs/context.h			\
								\
				include/log.h			\
				include/ipc.h			\
				include/socket.h		\
				include/list.h			\
				include/shm.h			\
				include/ptrace.h		\
				include/pie-util-fd.h		\
				include/util.h			\
				include/futex.h

bin_swapfd_SOURCES =		main.c				\
								\
				manager/swapfd.c		\
								\
				manager/swapfd.h		\
								\
				src/util.c			\
				src/log.c			\
				src/ptrace.c			\
				src/pie-util-fd.c		\
								\
				include/log.h			\
				include/util.h
				include/pie-util-fd.h		\
				include/ptrace.h

tags: ctags

.PHONY: tags
