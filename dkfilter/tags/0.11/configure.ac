dnl Initialize automake/autoconf
AC_INIT(dkfilter, 0.11)
AM_INIT_AUTOMAKE

dnl Check for Perl
AC_PATH_PROG(PERL, perl, perl)

dnl Check for Perl dependencies
local_CHECK_PERL_MODULE(Crypt::OpenSSL::RSA)
local_CHECK_PERL_MODULE(Mail::Address)
local_CHECK_PERL_MODULE(MIME::Base64)
local_CHECK_PERL_MODULE(Net::DNS)
local_CHECK_PERL_MODULE(Test::More)
local_CHECK_PERL_MODULE(Net::Server 0.89)

dnl Installation locations
perllibdir='${prefix}/lib'
AC_SUBST(perllibdir)

AC_OUTPUT([
	Makefile
	lib/Makefile
	lib/Mail/Makefile
	lib/Mail/DomainKeys/Makefile
	lib/Mail/DomainKeys/Key/Makefile
	lib/MSDW/Makefile
	lib/MSDW/SMTP/Makefile
	scripts/Makefile
	])
