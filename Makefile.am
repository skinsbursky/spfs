## Process this file with automake to produce Makefile.in
CLEANFILES = `find . -name *~`

AM_CFLAGS = -Wall -ggdb -D_GNU_SOURCE -iquote include/
AM_MAKEFLAGS = --no-print-directory

sbin_PROGRAMS = spfs spfs_client

spfs_SOURCES =	main.c		\
		gateway.c	\
		util.c		\
		proxy.c		\
		stub.c		\
		context.c	\
		log.c		\
		interface.c	\
		golem.c

spfs_CFLAGS = `pkg-config fuse --cflags --libs`
spfs_LDADD =
spfs_LDFLAGS = @LIBS@
spfs_DEPENDENCIES =


spfs_client_SOURCES = fuse_client.c

spfs_client_CFLAGS =
spfs_client_LDADD =
spfs_client_LDFLAGS =
spfs_client_DEPENDENCIES =

tags: ctags

.PHONY: tags
