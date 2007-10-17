dnl Initialize automake/autoconf
AC_INIT(dkimproxy, 1.0)
AM_INIT_AUTOMAKE

dnl Check for Perl
AC_PATH_PROG(PERL, perl, perl)

dnl Check for Perl dependencies
local_CHECK_PERL_MODULE(Mail::DKIM 0.20)
local_CHECK_PERL_MODULE(Error)
local_CHECK_PERL_MODULE(Net::Server 0.91)

dnl Installation locations
test -z "$perllibdir" && perllibdir='${prefix}/lib'
AC_SUBST(perllibdir)

AC_OUTPUT([
	Makefile
	lib/Makefile
	lib/MSDW/Makefile
	lib/MSDW/SMTP/Makefile
	scripts/Makefile
	])
