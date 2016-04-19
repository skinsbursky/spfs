## Process this file with automake to produce Makefile.in
CLEANFILES = `find . -name "*~"`

AM_CFLAGS = -Wall -Werror -ggdb -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
AM_MAKEFLAGS = --no-print-directory

sbin_PROGRAMS = bin/spfs bin/spfs-client bin/spfs-manager

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
								\
				include/log.h			\
				include/socket.h		\
				include/util.h

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
				manager/mount.c			\
				manager/spfs.c			\
				manager/freeze.c		\
								\
				manager/context.h		\
				manager/interface.h		\
				manager/mount.h			\
				manager/spfs.h			\
				manager/freeze.h		\
								\
				src/util.c			\
				src/socket.c			\
				src/ipc.c			\
				src/log.c			\
				src/shm.c			\
								\
				spfs/interface.h		\
				spfs/context.h			\
								\
				include/log.h			\
				include/ipc.h			\
				include/socket.h		\
				include/util.h

tags: ctags

.PHONY: tags
