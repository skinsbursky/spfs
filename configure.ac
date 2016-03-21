AC_INIT([spfs], [0.01], [skinsbursky@virtuozzo.org])
AM_INIT_AUTOMAKE
AM_PROG_CC_C_O

m4_ifdef([AM_SILENT_RULES],
	 [AM_SILENT_RULES([yes])],
	 [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

AC_GNU_SOURCE
AC_CONFIG_HEADERS([spfs_config.h])
AC_CONFIG_FILES([
		 Makefile
])

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

AC_OUTPUT

