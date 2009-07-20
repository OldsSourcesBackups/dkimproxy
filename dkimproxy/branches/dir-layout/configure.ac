dnl Initialize automake/autoconf
AC_INIT(dkimproxy, 1.2)
AM_INIT_AUTOMAKE

dnl Check for Perl
AC_PATH_PROG(PERL, perl, perl)

dnl Check for Perl dependencies
local_CHECK_PERL_MODULE(Mail::DKIM 0.30)
local_CHECK_PERL_MODULE(Error)
local_CHECK_PERL_MODULE(Net::Server 0.91)

dnl Installation locations
test -z "$perllibdir" && perllibdir='${pkglibdir}'
AC_SUBST(pkglibdir)
AC_SUBST(perllibdir)
test -z "$pkgsysconfdir" && pkgsysconfdir='${sysconfdir}/dkimproxy'
AC_SUBST(pkgsysconfdir)

AC_OUTPUT([
	Makefile
	lib/Makefile
	lib/MSDW/Makefile
	lib/MSDW/SMTP/Makefile
	scripts/Makefile
	])
