#!/usr/bin/perl

use strict;
use warnings;

use TestHarnass;
use Test::More tests => 7;

my $tester = TestHarnass->new;
$tester->{proxy_args} = [
		"--conf_file=listid_map.conf",
		];
$tester->start_servers;

my @signatures;
@signatures = $tester->generate_signatures("msg1.txt");
ok(@signatures == 0, "should be zero signatures");

@signatures = $tester->generate_signatures("lmsg1.txt");
ok(@signatures == 1, "should be one signature");
ok($signatures[0]->domain eq "kernel.org", "found expected d= argument");

@signatures = $tester->generate_signatures("lmsg2.txt");
ok(@signatures == 1, "should be one signature");
ok($signatures[0]->domain eq "lists.x.org", "found expected d= argument");

@signatures = $tester->generate_signatures("lmsg3.txt");
ok(@signatures == 1, "should be one signature");
ok($signatures[0]->domain eq "apache.org", "found expected d= argument");

$tester->shutdown_servers;

