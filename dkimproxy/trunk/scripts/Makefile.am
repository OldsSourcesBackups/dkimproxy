perldir = $(bindir)
perl_scripts = \
	dk_responder.pl \
	dkverify.pl \
	dkfilter.in \
	dkfilter.out \
	dkim_responder.pl \
	dkimsign.pl \
	dkimverify.pl \
	dkimproxy.in \
	dkimproxy.out

EXTRA_DIST = $(perl_scripts)

install-exec-hook:
	$(mkinstalldirs) "$(DESTDIR)$(perldir)";
	for f in $(perl_scripts); do \
		PERL="$(PERL)" PERL_INCLUDE="$(perllibdir)" \
		"$(PERL)" $(top_srcdir)/install-perl-script.pl $(srcdir)/$$f \
				$(DESTDIR)$(perldir)/$$f || exit $$?; \
		chmod +x $(DESTDIR)$(perldir)/$$f; \
	done

uninstall-hook:
	for f in $(perl_scripts); do \
		rm -f $(DESTDIR)$(perldir)/$$f; \
	done
