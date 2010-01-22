#!/usr/bin/perl -I../lib
#
# This file is part of DKIMproxy, an SMTP-proxy implementing DKIM.
# Copyright (c) 2005-2008 Messiah College.
# Written by Jason Long <jlong@messiah.edu>.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA  02110-1301, USA.
#

use strict;
use warnings;
use IO::File;
use MIME::Entity;

use Mail::DKIM 0.34;
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
my %canonicalized;
while (<STDIN>)
{
	s/\n\z/\015\012/;
	print $fh $_;

	push @message_lines, $_;

	if (/^Subject:\s*(.*)$/)
	{
		$subject = "Re: $1";
		if ($subject =~ /dkim|domainkey|test/i)
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
my @policies;
my @policy_results;
eval
{
	my $dkim = Mail::DKIM::Verifier->new(
			Debug_Canonicalization => \&debug_canonicalization,
		);
	$dkim->load($fh);

	$result = $dkim->result;
	$result_detail = $dkim->result_detail;

	if ($result && $result ne "none")
	{
		$attach_original_msg = 1;
	}

	@signatures = $dkim->signatures;
	@policies = $dkim->policies;
	@policy_results = map { $_->apply($dkim) } @policies;
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

my $hint_text = check_for_hints();

my $policy_results_text = "";
for (my $i = 0; $i < @policies; $i++)
{
	my $policy = $policies[$i];
	my $policy_result = $policy_results[$i];

	next unless $policy_result && $policy_result ne "neutral";
	my $location = $policy->location;
	my $policy_type = $policy->name;
	$policy_results_text .=
"This is the result after checking the $policy_type policy at \"$location\":
  $policy_result
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
my $PRODUCT = "Mail::DKIM";
my $VERSION = $Mail::DKIM::VERSION;
my $PRODUCT_URL = "http://dkimproxy.sourceforge.net/";

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
		$hint_text,
		"Thank you for using the dkimproxy DKIM Auto Responder.\n",
		"This Auto Responder tests the verification routines of $PRODUCT $VERSION.\n",
		"For more information about $PRODUCT, see $PRODUCT_URL\n",
		"\n",
		"If you have any questions about this automated tester, or if you\n",
		"received this message in error, please send a note to\n",
		FROM_ADDR . "\n",
		]);

if ($attach_original_msg)
{
	# part two, original message
	my @lines = @message_lines;
	s/\015\012$/\n/s foreach (@lines);

	$top->attach(
		Type => "text/plain",
		Filename => "rfc822.txt",
		Disposition => "attachment",
		Data => \@message_lines);
}
if ($attach_original_msg)
{
	# part three, canonicalized message
	# FIXME - by attaching it as text/plain, the linefeed characters
	# are subject to conversion during the encoding/decoding process.
	# It may be better to attach as a binary object?
	foreach my $canonicalized (values %canonicalized)
	{
		$top->attach(
			Type => "application/octet-stream",
			Encoding => "base64",
			Filename => "canonicalized.txt",
			Disposition => "attachment",
			Data => $canonicalized->{text});
	}
}

# send it
open MAIL, "| /usr/sbin/sendmail -t -i " . RESULT_BCC
	or die "open: $!";
$top->print(\*MAIL);
close MAIL;

sub make_auth_result
{
	my $signature = shift;

	my $type = $signature->isa("Mail::DKIM::DkSignature")
		? "domainkeys" : "dkim";
	my $tag = $signature->can("identity_source")
		? $signature->identity_source : "header.i";

	return "$type=" . $signature->result_detail
		. " $tag=" . $signature->identity;
}

sub debug_canonicalization
{
	my ($text, $canonicalization) = @_;

	$canonicalized{$canonicalization}
		||= { text => "", canon => $canonicalization };
	$canonicalized{$canonicalization}->{text} .= $text;
}

sub check_for_hints
{
	my @hints;

	if ($result_detail =~ /body has been altered/)
	{
		if (grep /^\./, @message_lines)
		{
			push @hints, "Your message contains lines beginning with a period, so check that\n   your implementation signs before dot stuffing.";
		}
	}

	if (@hints)
	{
		return "*** WHY DID MY MESSAGE FAIL? ***\n"
		. "Looking at your specific message, this auto-responder suggests\n"
		. "checking the following:\n"
		. join("", map " * $_\n", @hints). "\n";
	}
	return "";
}
