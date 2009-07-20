perldir = $(bindir)
perl_scripts = \
	dkim_responder.pl \
	dkimsign.pl \
	dkimverify.pl \
	dkimproxy.in \
	dkimproxy.out

man_MANS = \
	dkimproxy_in.8 \
	dkimproxy_out.8

dkimproxy_in.8: dkimproxy.in
	pod2man "$(srcdir)/$<" > $@

dkimproxy_out.8: dkimproxy.out
	pod2man "$(srcdir)/$<" > $@

pkgsysconf_DATA = dkimproxy_in.conf.example dkimproxy_out.conf.example

EXTRA_DIST = $(perl_scripts) $(pkgsysconf_DATA) $(man_MANS)
MAINTAINERCLEANFILES = $(man_MANS)

install-exec-hook:
	$(mkinstalldirs) '$(DESTDIR)$(perldir)';
	for f in $(perl_scripts); do \
		PERL="$(PERL)" PERL_INCLUDE="$(perllibdir)" \
		"$(PERL)" "$(top_srcdir)/install-perl-script.pl" "$(srcdir)/$$f" \
				"$(DESTDIR)$(perldir)/$$f" || exit $$?; \
		chmod +x "$(DESTDIR)$(perldir)/$$f"; \
	done

uninstall-hook:
	for f in $(perl_scripts); do \
		rm -f "$(DESTDIR)$(perldir)/$$f"; \
	done
