## Process this file with automake to produce Makefile.in
CLEANFILES = `find . -name "*~"`

AM_CFLAGS = -Wall -ggdb -D_GNU_SOURCE -iquote include/
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
				src/util.c			\
				src/log.c			\
				src/socket.c			\
								\
				include/context.h		\
				include/log.h			\
				include/socket.h		\
				include/spfs_interface.h	\
				include/util.h

bin_spfs_CFLAGS = `pkg-config fuse --cflags --libs`
bin_spfs_LDADD =
bin_spfs_LDFLAGS = @LIBS@
bin_spfs_DEPENDENCIES =


bin_spfs_client_SOURCES =	client/main.c			\
				include/spfs_interface.h	\
				include/util.h

bin_spfs_client_CFLAGS =
bin_spfs_client_LDADD =
bin_spfs_client_LDFLAGS =
bin_spfs_client_DEPENDENCIES =

bin_spfs_manager_SOURCES =	manager/main.c			\
								\
				src/util.c			\
				src/socket.c			\
				src/log.c			\
								\
				include/log.h			\
				include/socket.h		\
				include/util.h

bin_spfs_manager_CFLAGS =
bin_spfs_manager_LDADD =
bin_spfs_manager_LDFLAGS =
bin_spfs_manager_DEPENDENCIES =

tags: ctags

.PHONY: tags
