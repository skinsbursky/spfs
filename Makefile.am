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
				spfs/golem.c			\
				spfs/interface.c		\
								\
				spfs/interface.h		\
				spfs/context.h			\
								\
				src/util.c			\
				src/log.c			\
				src/socket.c			\
				src/ipc.c			\
								\
				include/log.h			\
				include/socket.h		\
				include/util.h

bin_spfs_CFLAGS = `pkg-config fuse --cflags --libs` $(AM_CFLAGS)
bin_spfs_LDADD =
bin_spfs_LDFLAGS = @LIBS@
bin_spfs_DEPENDENCIES =


bin_spfs_client_SOURCES =	client/main.c			\
								\
				src/socket.c			\
				src/log.c			\
				src/util.c			\
								\
				spfs/interface.h		\
								\
				include/socket.h		\
				include/util.h

bin_spfs_client_CFLAGS = $(AM_CFLAGS)
bin_spfs_client_LDADD =
bin_spfs_client_LDFLAGS =
bin_spfs_client_DEPENDENCIES =

bin_spfs_manager_SOURCES =	manager/main.c			\
				manager/context.c		\
				manager/interface.c		\
				manager/mount.c			\
								\
				manager/context.h		\
				manager/interface.h		\
				manager/mount.h			\
								\
				src/util.c			\
				src/socket.c			\
				src/log.c			\
								\
				include/log.h			\
				include/socket.h		\
				include/util.h

bin_spfs_manager_CFLAGS = $(AM_CFLAGS)
bin_spfs_manager_LDADD =
bin_spfs_manager_LDFLAGS =
bin_spfs_manager_DEPENDENCIES =

tags: ctags

.PHONY: tags
