dnl Process this file with autoconf to produce a configure script.
AC_INIT
AC_PREREQ(2.50)
AC_CONFIG_SRCDIR([configure.ac])
AM_INIT_AUTOMAKE(iksemel,1.5)
AM_CONFIG_HEADER(include/config.h)

AC_CANONICAL_HOST

dnl Checks for programs
AC_PROG_CC
AC_PROG_INSTALL
AC_CHECK_TOOL(OBJDUMP, objdump, :)
AM_PROG_LIBTOOL
AC_LANG_C

dnl Checks for header files
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h strings.h errno.h)

dnl Checks for typedefs and structures
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])

dnl Checks for library functions
AC_CHECK_FUNCS(getopt_long)

dnl Check -Wall flag of GCC
if test "x$GCC" = "xyes"; then
  if test -z "`echo "$CFLAGS" | grep "\-Wall" 2> /dev/null`" ; then
    CFLAGS="$CFLAGS -Wall"
  fi
fi


dnl Generating makefiles
AC_CONFIG_FILES([
Makefile
src/Makefile
include/Makefile
])
AC_OUTPUT
