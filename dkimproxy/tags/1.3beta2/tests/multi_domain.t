#!/usr/bin/perl

use strict;
use warnings;

use TestHarnass;
use Test::More tests => 7;

my $tester = TestHarnass->new;
$tester->{proxy_args} = [
		"--conf_file=multi_domain.conf",
		];
$tester->start_servers;

my @signatures;
eval {

@signatures = $tester->generate_signatures("msg1.txt");
ok(@signatures == 2, "should be two signatures");
ok($signatures[0]->domain eq "domain1.example", "found expected d= argument");
ok($signatures[1]->domain eq "domain1.example", "found expected d= argument");

@signatures = $tester->generate_signatures("msg2.txt");
ok(@signatures == 2, "should be two signatures");
ok($signatures[0]->domain eq "domain2.example", "found expected d= argument");
ok($signatures[1]->domain eq "domain2.example", "found expected d= argument");

@signatures = $tester->generate_signatures("msg3.txt");
ok(@signatures == 0, "should be zero signatures");

};
my $E = $@;
$tester->shutdown_servers;
die $E if $E;
