html_files = \
	download.html \
	faq.html \
	index.html \
	postfix-inbound-howto.html \
	postfix-outbound-howto.html \
	support.html \
	usage.html

include_files = common.tt2 nav.inc

all: $(html_files)


$(html_files): %.html: %.html.in $(include_files)
	ttml $< > $@
