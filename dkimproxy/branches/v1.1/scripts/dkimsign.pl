#!/usr/bin/perl -I../lib
#
# This file is part of DKIMproxy, an SMTP-proxy implementing DKIM.
# Copyright (c) 2005-2008 Messiah College.
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

use Mail::DKIM 0.17;
use Mail::DKIM::Signer;
use Getopt::Long;
use Pod::Usage;

#enable support for "pretty" signatures, if available
eval "require Mail::DKIM::TextWrap";

my $method = "simple";
my $selector = "selector1";
my $debug_canonicalization;
my $help;
GetOptions(
		"method=s" => \$method,
		"selector=s" => \$selector,
		"debug-canonicalization=s" => \$debug_canonicalization,
		"help|?" => \$help,
		)
	or pod2usage(2);
pod2usage(1) if $help;
pod2usage("Error: unrecognized argument(s)")
	unless (@ARGV == 0);

my $dkim = new Mail::DKIM::Signer(
		Policy => "MySignerPolicy",
		Algorithm => "rsa-sha1",
		Method => $method,
		Selector => $selector,
		KeyFile => "private.key",
		Debug_Canonicalization => $debug_canonicalization);

while (<STDIN>)
{
	chomp;
	$dkim->PRINT("$_\015\012");
}
$dkim->CLOSE;

print $dkim->signature->as_string . "\n";

package MySignerPolicy;
use Mail::DKIM::SignerPolicy;
use base "Mail::DKIM::SignerPolicy";

sub apply
{
	my ($self, $signer) = @_;

	$signer->domain($signer->message_sender->host);
	return 1;
}

__END__

=head1 NAME

dkimsign.pl - computes a DKIM signature for an email message

=head1 SYNOPSIS

  dkimsign.pl [options] < original_email.txt
    options:
      --method=METHOD
      --selector=SELECTOR
      --debug-canonicalization=FILE

  dkimsign.pl --help
    to see a full description of the various options

=head1 OPTIONS

=over

=item B<--method>

Determines the desired canonicalization method. Possible values are
simple, simple/simple, simple/relaxed, relaxed, relaxed/relaxed,
relaxed/simple.

=item B<--debug-canonicalization>

Outputs the canonicalized message to the specified file, in addition
to computing the DKIM signature. This is helpful for debugging
canonicalization methods.

=back

=cut
