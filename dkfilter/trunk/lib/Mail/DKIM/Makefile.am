SUBDIRS = Algorithm Canonicalization

dkimdir = $(perllibdir)/Mail/DKIM
dkim_SCRIPTS = \
	Common.pm \
	MessageParser.pm \
	PublicKey.pm \
	Signature.pm \
	Signer.pm \
	SignerPolicy.pm \
	SigningFilter.pm \
	Verifier.pm

EXTRA_DIST = \
	$(dkim_SCRIPTS) \
	test_signing_filter.pl \
	test_verifying_filter.pl \
	HACKING.DKIM
