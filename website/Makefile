html_files = \
	download.html \
	faq.html \
	index.html \
	newsarchive.html \
	postfix-inbound-howto.html \
	postfix-outbound-howto.html \
	support.html \
	usage.html
manual_files = \
	dkimproxy.in.html \
	dkimproxy.out.html

include_files = common.tt2 nav.inc

all: $(html_files) $(manual_files)

upload: all
	scp $(html_files) jasonlong,dkimproxy@web.sourceforge.net:htdocs/
	scp $(manual_files) jasonlong,dkimproxy@web.sourceforge.net:htdocs/manual/

$(html_files): %.html: %.html.in $(include_files)
	ttml $< > $@
$(manual_files): %.html: ../scripts/%
	pod2html $< > $@
