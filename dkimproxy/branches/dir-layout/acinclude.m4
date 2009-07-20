dnl ---------------------------------------------------
dnl local_CHECK_PERL_MODULE(MODULE[ VERSION])
dnl ---------------------------------------------------
dnl
dnl Examples:
dnl   local_CHECK_PERL_MODULE(Mail::DKIM 0.17)
dnl   local_CHECK_PERL_MODULE(Error)
dnl   local_CHECK_PERL_MODULE(Net::Server 0.89)

AC_DEFUN([local_CHECK_PERL_MODULE],
  [

AC_MSG_CHECKING(for Perl module '$1')

if "$PERL" -e 'use $1 $2' 2>/dev/null; then
	AC_MSG_RESULT(found)
else
	AC_MSG_RESULT(not found)
	AC_MSG_ERROR(requested Perl module '$1' not found)
fi
])
