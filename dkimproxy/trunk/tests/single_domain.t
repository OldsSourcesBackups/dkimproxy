#!/usr/bin/perl

use strict;
use warnings;

my $path = "../scripts";
my @signatures;
@signatures = generate_signatures("msg1.txt");


print "ok\n";

sub generate_signatures
{
	my $msgfile = shift;

	system("$path/dkimproxy.out",
		"--conf_file=single_domain.conf",
		"--pidfile=pidfile",
		"--daemonize=1",
		"127.0.0.1:20025",
		"smtp.messiah.edu:25",
		) == 0 or exit 2;
	sleep 2;


	return ();
}
