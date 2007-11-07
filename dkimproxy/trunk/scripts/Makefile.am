perldir = $(bindir)
perl_scripts = \
	dkim_responder.pl \
	dkimsign.pl \
	dkimverify.pl \
	dkimproxy.in \
	dkimproxy.out

sysconf_DATA = dkimproxy_in.conf.example dkimproxy_out.conf.example

EXTRA_DIST = $(perl_scripts) $(sysconf_DATA)

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
