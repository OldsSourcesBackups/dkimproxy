#!/usr/bin/perl -I../lib
#
# Copyright (c) 2005 Messiah College. This program is free software.
# You can redistribute it and/or modify it under the terms of the
# GNU Public License as found at http://www.fsf.org/copyleft/gpl.html.
#
# Written by Jason Long, jlong@messiah.edu.

use strict;
use warnings;
use IO::File;
use MIME::Entity;

use Mail::DKIM 0.27;
use Mail::DKIM::Verifier;

use constant FROM_ADDR => 'admin@dkimtest.jason.long.name';
use constant SENDER_ADDR => 'nobody@messiah.edu';
use constant DEFAULT_SUBJECT => "Results of DKIM test";
use constant RESULT_BCC => 'results@dkimtest.jason.long.name';

# create a temporary file for storing the message contents
my $fh = IO::File::new_tmpfile;

my $from_line = <STDIN>;
unless ($from_line =~ /^From (\S+)/)
{
	die "invalid delivery (no From line)\n";
}

my $from = $1;
my $from_header;
my $subject;
my $attach_original_msg;

# read message from stdin, catching from address and subject
my @message_lines;
my $canonicalized = "";
while (<STDIN>)
{
	s/\n\z/\015\012/;
	print $fh $_;

	push @message_lines, $_;

	if (/^Subject:\s*(.*)$/)
	{
		$subject = "Re: $1";
		if ($subject =~ /dkim|test/i)
		{
			$attach_original_msg = 1;
		}
	}
	elsif (/^From:\s*(.*)$/)
	{
		$from_header = $1;
		$from_header =~ s/^.*<(.*)>.*$/$1/;
	}
}

# rewind message, and have DKIM verify it
$fh->seek(0, 0);
my $result;
my $result_detail;
my @signatures;
my $a_policy;
my $a_policy_result;
my $s_policy;
my $s_policy_result;
eval
{
	my $dkim = Mail::DKIM::Verifier->new(
			Debug_Canonicalization => \$canonicalized,
		);
	$dkim->load($fh);

	$result = $dkim->result;
	$result_detail = $dkim->result_detail;

	if ($result && $result ne "none")
	{
		$attach_original_msg = 1;
	}

	@signatures = $dkim->signatures;

	$a_policy = $dkim->fetch_author_policy;
	$a_policy_result = $a_policy->apply($dkim);
	$s_policy = $dkim->fetch_sender_policy;
	$s_policy_result = $s_policy->apply($dkim);
};
if ($@)
{
	my $E = $@;
	chomp $E;
	$result = "temperror";
	$result_detail = "$result ($E)";
}

# sanitize subject
if ($subject =~ /confirm/i)
{
	$subject = "";
}
$subject =~ s/(\w{10})\w+/$1/g;

$subject ||= DEFAULT_SUBJECT;
if ($from_header && $ENV{EXTENSION} && $ENV{EXTENSION} eq "usefrom")
{
	$from = $from_header;
}

# create a response message
my $top = MIME::Entity->build(
		Type => "multipart/mixed",
		From => FROM_ADDR,
		Sender => SENDER_ADDR,
		To => $from,
		Subject => $subject,
	);

my $verify_results_text =
		"This is the overall result of the message verification:\n" .
		"  $result_detail\n" .
		"\n";
if (@signatures > 1)
{
	$verify_results_text .=
		"These are the results of each signature (in order):\n";
	foreach my $sig (@signatures)
	{
		$verify_results_text .= "  " . make_auth_result($sig) . "\n";
	}
	$verify_results_text .= "\n";
}

my $policy_results_text = "";
if ($a_policy_result && $a_policy_result ne "neutral")
{
	my $location = $a_policy->location;
	$policy_results_text =
"This is the result after checking the DKIM policy at \"$location\":
  $a_policy_result
\n";
}
if ($s_policy_result && $s_policy_result ne "neutral")
{
	my $location = $s_policy->location;
	$policy_results_text =
"This is the result after checking the DomainKeys policy at \"$location\":
  $s_policy_result
\n";
}

my $attach_text;
if ($attach_original_msg)
{
	$attach_text =
"Attached to this message you will find the original message as plain text,
as well as the canonicalized version of the message (if available).

";
}
else
{
	$attach_text =
"To prevent abuse, the original message sent to this address has not
been included. Next time, try putting the words \"dkim\" or \"test\" in the
subject.

";
}

# part one, literal text containing result of test
my $PRODUCT = "Mail::DKIM " . $Mail::DKIM::VERSION;
$top->attach(
	Type => "text/plain",
	Data => [
		"*** This is an automated response ***\n\n",
		$verify_results_text,
		$policy_results_text,
		$attach_text,
		"Please note if your message had multiple signatures, that this\n",
		"auto-responder looks for ANY passing signature, including DomainKeys\n",
		"signatures.\n",
		"\n",
		"Thank you for using the dkimproxy DKIM Auto Responder.\n",
		"This Auto Responder tests the verification routines of $PRODUCT.\n",
		"For more information about Mail::DKIM, see http://jason.long.name/dkimproxy/\n",
		"\n",
		"If you have any questions about this automated tester, or if you\n",
		"received this message in error, please send a note to\n",
		FROM_ADDR . "\n",
		]);

if ($attach_original_msg)
{
	# part two, original message
	$top->attach(
		Type => "text/plain",
		Filename => "rfc822.txt",
		Disposition => "attachment",
		Data => \@message_lines);
}
if ($attach_original_msg && length($canonicalized))
{
	# part three, canonicalized message
	# FIXME - by attaching it as text/plain, the linefeed characters
	# are subject to conversion during the encoding/decoding process.
	# It may be better to attach as a binary object?
	$top->attach(
		Type => "application/octet-stream",
		Encoding => "base64",
		Filename => "canonicalized.txt",
		Disposition => "attachment",
		Data => $canonicalized);
}

# send it
open MAIL, "| /usr/sbin/sendmail -t -i " . RESULT_BCC
	or die "open: $!";
$top->print(\*MAIL);
close MAIL;

sub make_auth_result
{
	my $signature = shift;

	if ($signature->isa("Mail::DKIM::DkSignature"))
	{
		return "domainkeys=" . $signature->result_detail;
	}
	else
	{
		return "dkim=" . $signature->result_detail
			. " i=" . $signature->identity;
	}
}
