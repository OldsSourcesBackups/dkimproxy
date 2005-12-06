#!/usr/bin/perl -I../lib

use strict;
use warnings;

use Mail::DKIM::Signer;
use Getopt::Long;

my $method = "simple";
my $debug_canonicalization;
GetOptions(
		"method=s" => \$method,
		"debug-canonicalization=s" => \$debug_canonicalization,
		)
	or die "Error: invalid argument(s)\n";

my $dkim = new Mail::DKIM::Signer(
		Policy => "MySignerPolicy",
		Algorithm => "rsa-sha1",
		Method => $method,
		Selector => "selector1",
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
