AC_INIT([spfs], [0.09.001], [skinsbursky@virtuozzo.org])

m4_ifdef([AM_SILENT_RULES],
	 [AM_SILENT_RULES([yes])],
	 [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

AM_INIT_AUTOMAKE([subdir-objects])
AM_PROG_CC_C_O

AC_GNU_SOURCE
AC_CONFIG_HEADERS([spfs_config.h])
AC_CONFIG_FILES([
		 Makefile
])

AC_CHECK_FUNCS([fork setxattr fdatasync utimensat])
AC_CHECK_FUNCS([posix_fallocate fstatat openat readlinkat])

AC_CHECK_HEADER(
		[sys/capability.h],
		[],
		[AC_MSG_ERROR([*** install libcap-dev(el)])],
		[])

AC_CHECK_HEADER(
		[libnl3/netlink/msg.h],
		[],
		[AC_MSG_ERROR([*** install libnl3-devel (libnl-3-dev)])],
		[])

AC_CHECK_LIB(
	     [fuse],
	     [fuse_mount],
	     [],
	     [AC_MSG_ERROR([*** libfuse not found.])
	     ])

AC_CHECK_LIB(
	     [pthread],
	     [pthread_create],
	     [],
	     [AC_MSG_ERROR([*** libpthread not found.])
	     ])

AC_CHECK_LIB(
	     [ulockmgr],
	     [ulockmgr_op],
	     [],
	     [AC_MSG_ERROR([*** libulockmgr not found.])
	     ])

AC_CHECK_LIB(
	     [nl-3],
	     [nla_attr_size],
	     [],
	     [AC_MSG_ERROR([*** libnl-3 not found.])
	     ])

FUSE_USE_VERSION=26
AC_DEFINE_UNQUOTED(FUSE_USE_VERSION, $FUSE_USE_VERSION, [spfs])

FS_NAME=spfs
AC_DEFINE_UNQUOTED(FS_NAME, "$FS_NAME", [spfs])

CLIENT_NAME=spfs-client
AC_DEFINE_UNQUOTED(CLIENT_NAME, "$CLIENT_NAME", [spfs])

MANAGER_NAME=spfs-manager
AC_DEFINE_UNQUOTED(MANAGER_NAME, "$MANAGER_NAME", [spfs])

AC_OUTPUT

