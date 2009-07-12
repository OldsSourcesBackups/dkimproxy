SUBDIRS = lib scripts

EXTRA_DIST = \
	TODO \
	install-perl-script.pl \
	smtpprox.ChangeLog \
	smtpprox.README \
	smtpprox.TODO \
	sample-dkim-init-script.sh

rfcs = rfc4870.txt rfc4871.txt rfc2821.txt rfc5322.txt rfc4407.txt
drafts = draft-ietf-dkim-ssp-09.txt
download-rfcs: $(rfcs) $(drafts)

$(rfcs) :
	curl -o $@ http://www.ietf.org/rfc/$@
$(drafts) :
	curl -o $@ http://www.ietf.org/internet-drafts/$@
