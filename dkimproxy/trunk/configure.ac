dnl Initialize automake/autoconf
AC_INIT(dkimproxy, 0.13)
AM_INIT_AUTOMAKE

dnl Check for Perl
AC_PATH_PROG(PERL, perl, perl)

dnl Installation locations
perllibdir='${prefix}/lib'
AC_SUBST(perllibdir)

AC_OUTPUT([
	Makefile
	lib/Makefile
	lib/MSDW/Makefile
	lib/MSDW/SMTP/Makefile
	scripts/Makefile
	tests/Makefile
	tests/can/Makefile
	tests/variant_keys/Makefile
	tests/variant_sigs/Makefile
	])
