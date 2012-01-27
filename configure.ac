dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.61)
AC_INIT([psmisc],[22.16])
AC_CONFIG_SRCDIR([src/comm.h])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([1.10])
AC_LANG([C])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_LN_S

dnl checks for options
# SELinux support - off by default
AC_SUBST([WITH_SELINUX])
AC_ARG_ENABLE([selinux],
  [AS_HELP_STRING([--enable-selinux], [Enable Security-Enhanced Linux features])],
  [enable_selinux=$enableval],
  [enable_selinux="no"])
if test "$enable_selinux" = "yes"; then
  AC_DEFINE([WITH_SELINUX], [1], [Use Security-Enhanced Linux features])
  AC_CHECK_LIB([selinux], [getfilecon], [SELINUX_LIB=-lselinux], [
     AC_MSG_ERROR([Cannot find selinux static library]) ])
fi
AC_SUBST([SELINUX_LIB])

# Call fork before all stat calls to stop hanging on NFS mounts
AC_SUBST([WITH_TIMEOUT_STAT])
AC_ARG_ENABLE([timeout_stat],
  [AS_HELP_STRING([--enable-timeout-stat], [Use a timeout on stat calls])],
  [enable_timeout_stat=$enableval],
  [enable_timeout_stat="no"])
if test "$enable_timeout_stat" = "yes"; then
  AC_DEFINE([WITH_TIMEOUT_STAT], [1], [Use timeout on stat calls])
fi

# Enable hardened compile and link flags
AC_ARG_ENABLE([harden_flags],
  [AS_HELP_STRING([--disable-harden-flags], [disable hardened compilier and linker flags])],
  [enable_harden_flags=$enableval],
  [enable_harden_flags="yes"])

dnl ipv4 only option
AC_SUBST([WITH_IPV6])
AC_ARG_ENABLE([ipv6],
  [AS_HELP_STRING([--disable-ipv6], [Disable IPv6 checks (for uClibc)])],
  [enable_ipv6=$enableval],
  [enable_ipv6="yes"])
if test "$enable_ipv6" = "yes"; then
  AC_DEFINE([WITH_IPV6], [1], [Use IPv6 checks])
fi

dnl Checks for libraries.
AC_CHECK_LIB([tinfo], [tgetent], [TERMCAP_LIB=-ltinfo],
  [ AC_CHECK_LIB([ncurses], [tgetent], [TERMCAP_LIB=-lncurses],
    [ AC_CHECK_LIB([termcap], [tgetent], [TERMCAP_LIB=-ltermcap], 
      [ AC_MSG_ERROR([Cannot find tinfo, ncurses or termcap libraries])
	  ] )
	] )
  ] )
AC_SUBST([TERMCAP_LIB])

dnl Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h langinfo.h libintl.h limits.h locale.h mntent.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h termios.h unistd.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_TYPE_UID_T

# Check that harden CFLAGS will compile
AS_IF([test "$enable_harden_flags" = "yes"],
  HARDEN_CFLAGS="-fstack-protector --param=ssp-buffer-size=4 -Wformat -Wformat-security -Werror=format-security"
  [ AC_MSG_CHECKING([compiler supports harden flags])
  save_harden_cflags="$CFLAGS"
  CFLAGS="$CFLAGS $HARDEN_CFLAGS"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,,)],
      [AC_MSG_RESULT([yes])],
     [AC_MSG_RESULT([no]); HARDEN_CFLAGS='']
    )
  CFLAGS="$save_harden_cflags"],
  [HARDEN_CFLAGS=""])
AC_SUBST([HARDEN_CFLAGS])

dnl Check for language stuff
AM_GNU_GETTEXT_VERSION([0.16.1])
AM_GNU_GETTEXT([external])

dnl Must be after the gettext stuff as it sets build_cpu
AC_CHECK_MEMBERS([struct user_regs_struct.orig_eax,
		struct user_regs_struct.eax,
		struct user_regs_struct.ebx,
		struct user_regs_struct.ecx,
		struct user_regs_struct.edx,
		struct user_regs_struct.orig_rax,
		struct user_regs_struct.rax,
		struct user_regs_struct.rdi,
		struct user_regs_struct.rsi,
		struct user_regs_struct.rdx], [],[],
    [#include <bits/types.h>
     #include <sys/user.h>])
AC_CHECK_MEMBERS([struct pt_regs.orig_gpr3,
		struct pt_regs.gpr], [],[], [#include <linux/ptrace.h>])
AC_CHECK_MEMBERS([struct pt_regs.uregs],[],[], [#include <asm/ptrace.h>])
AC_CHECK_MEMBERS([struct pt_regs.regs,
                  struct pt_regs.cp0_status],[],[], [#include <asm/ptrace.h>])

AM_CONDITIONAL(WANT_PEEKFD_I386,
 test $ac_cv_member_struct_user_regs_struct_orig_eax = yes &&
   test $ac_cv_member_struct_user_regs_struct_eax = yes &&
   test $ac_cv_member_struct_user_regs_struct_ebx = yes &&
   test $ac_cv_member_struct_user_regs_struct_ecx = yes &&
   test $ac_cv_member_struct_user_regs_struct_edx = yes )
AM_CONDITIONAL(WANT_PEEKFD_X86_64,
 test $ac_cv_member_struct_user_regs_struct_orig_rax = yes &&
   test $ac_cv_member_struct_user_regs_struct_rax = yes &&
   test $ac_cv_member_struct_user_regs_struct_rdi = yes &&
   test $ac_cv_member_struct_user_regs_struct_rsi = yes &&
   test $ac_cv_member_struct_user_regs_struct_rdx = yes )
AM_CONDITIONAL(WANT_PEEKFD_PPC,
   test $ac_cv_member_struct_pt_regs_orig_gpr3 = yes &&
   test $ac_cv_member_struct_pt_regs_gpr = yes )
AM_CONDITIONAL(WANT_PEEKFD_ARM,
   test $ac_cv_member_struct_pt_regs_uregs = yes)
AM_CONDITIONAL(WANT_PEEKFD_MIPS,
   test $build_cpu = mipsel &&
   test $ac_cv_member_struct_pt_regs_regs = yes &&
   test $ac_cv_member_struct_pt_regs_cp0_status = yes)

dnl Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_GETMNTENT
AC_PROG_GCC_TRADITIONAL
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_CHECK_FUNCS([atexit getmntent memset nl_langinfo rawmemchr regcomp rpmatch setlocale socket strcasecmp strchr strdup strerror strpbrk strrchr strtoul])

dnl Checks for Large File System
AC_SYS_LARGEFILE

AC_CONFIG_FILES([Makefile
		 doc/Makefile
		 src/Makefile
		 icons/Makefile
		 po/Makefile.in])
AC_OUTPUT
