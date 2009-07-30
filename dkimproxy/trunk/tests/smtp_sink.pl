#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Long;
my $port = 20025;
GetOptions(
	"port=i" => \$port,
	) or exit 2;

use Net::SMTP::Server;
use Net::SMTP::Server::Client;

my $server = Net::SMTP::Server->new('localhost', $port)
	or die("$!\n");
while (my $conn = $server->accept())
{
	my $client = Net::SMTP::Server::Client->new($conn)
		or die "client connection: $!\n";
	$client->process
		or next;

	use URI::Escape;
	use IO::Handle;

	print uri_escape($client->{MSG}) . "\n";
	STDOUT->flush;
}
