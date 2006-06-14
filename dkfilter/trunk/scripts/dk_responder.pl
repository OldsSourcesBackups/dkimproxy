#!/usr/bin/perl -I../lib
#
# Copyright (c) 2005 Messiah College. This program is free software.
# You can redistribute it and/or modify it under the terms of the
# GNU Public License as found at http://www.fsf.org/copyleft/gpl.html.
#

use strict;
use warnings;
use IO::File;
use MIME::Entity;

use DKMessage;

use constant FROM_ADDR => 'admin@dktest.jason.long.name';
use constant DEFAULT_SUBJECT => "Results of Domain Keys test";
use constant RESULT_BCC => 'results@dktest.jason.long.name';

# create a temporary file for storing the message contents
my $fh = IO::File::new_tmpfile;

my $from_line = <STDIN>;
unless ($from_line =~ /^From (\S+)/)
{
	die "invalid delivery (no From line)\n";
}

my $from = $1;
my $subject = DEFAULT_SUBJECT;

# read message from stdin, catching from address and subject
my @message_lines;
while (<STDIN>)
{
	print $fh $_;
	push @message_lines, $_;

	if (/^Subject:\s*(.*)$/)
	{
		$subject = "Re: $1";
	}
}

# rewind message, and have DomainKeys verify it
$fh->seek(0, 0);
my $result;
my $result_detail;
eval
{
	my $mess = DKMessage->new_from_handle($fh);
	$result = $mess->verify;
	$result_detail = $mess->result_detail;
};
if ($@)
{
	my $E = $@;
	chomp $E;
	$result = "temperror";
	$result_detail = "$result ($E)";
}

# create a response message
my $top = MIME::Entity->build(
		Type => "multipart/mixed",
		From => FROM_ADDR,
		To => $from,
		Subject => $subject);

# part one, literal text containing result of test
$top->attach(
	Type => "text/plain",
	Data => [
		"*** This is an automated response ***\n\n",
		"This is the result of the message verification:\n",
		"  $result_detail\n",
		"\n",
		"Attached you will find the original message as plain text.\n\n",
		"Thank you for using the dkfilter Domain Key Auto Responder.\n",
		"This Auto Responder tests the verification routines of dkfilter-0.10.\n",
		"For more information about dkfilter, see http://jason.long.name/dkfilter/\n",
		"\n",
		"If you have any questions about this automated tester, or if you\n",
		"received this message in error, please send a note to\n",
		FROM_ADDR . "\n",
		]);

# part two, original message
$top->attach(
	Type => "text/plain",
	Filename => "rfc822.txt",
	Data => \@message_lines);

# send it
open MAIL, "| /usr/sbin/sendmail -t -i " . RESULT_BCC
	or die "open: $!";
$top->print(\*MAIL);
close MAIL;
