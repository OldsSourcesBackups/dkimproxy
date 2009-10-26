#!/usr/bin/perl

use strict;
use warnings;

use TestHarnass;
use Test::More tests => 9;

my $tester = TestHarnass->new;
$tester->make_private_key("/tmp/private.key");
{
	$tester->{proxy_args} = [
		"--domain=domain1.example",
		"--keyfile=/tmp/private.key",
		"--selector=s1",
		"--method=relaxed",
		];
	$tester->start_servers;

	my @signatures;
	eval {

	@signatures = $tester->generate_signatures("msg1.txt");
	ok(@signatures == 1, "should be one signature");
	print "# " . $signatures[0]->as_string . "\n";
	ok($signatures[0]->domain eq "domain1.example", "found expected d= argument");
	ok($signatures[0]->method =~ /^relaxed/, "found expected c= argument");
	
	};
	my $E = $@;
	$tester->shutdown_servers;
	die $E if $E;
}

{
	$tester->{proxy_args} = [
		"--domain=domain1.example",
		"--keyfile=/tmp/private.key",
		"--selector=s1",
		"--method=simple",
		];
	$tester->start_servers;

	my @signatures;
	eval {

	@signatures = $tester->generate_signatures("msg1.txt");
	ok(@signatures == 1, "should be one signature");
	print "# " . $signatures[0]->as_string . "\n";
	ok($signatures[0]->domain eq "domain1.example", "found expected d= argument");
	ok($signatures[0]->method =~ /^simple/, "found expected c= argument");

	};
	my $E = $@;
	$tester->shutdown_servers;
	die $E if $E;
}

{
	$tester->{proxy_args} = [
		"--domain=domain1.example",
		"--keyfile=/tmp/private.key",
		"--selector=s1",
		"--method=relaxed/relaxed",
		];
	$tester->start_servers;

	my @signatures;
	eval {

	@signatures = $tester->generate_signatures("msg1.txt");
	ok(@signatures == 1, "should be one signature");
	print "# " . $signatures[0]->as_string . "\n";
	ok($signatures[0]->domain eq "domain1.example", "found expected d= argument");
	ok($signatures[0]->method eq "relaxed/relaxed", "found expected c= argument");

	};
	my $E = $@;
	$tester->shutdown_servers;
	die $E if $E;
}

{
	$tester->{proxy_args} = [
		"--conf_file=methods1.cfg",
		];
	$tester->start_servers;

	my @signatures;
	eval {

	@signatures = $tester->generate_signatures("msg1.txt");
	ok(@signatures == 1, "should be one signature");
	print "# " . $signatures[0]->as_string . "\n";
	ok($signatures[0]->domain eq "domain1.example", "found expected d= argument");
	ok($signatures[0]->method eq "relaxed/relaxed", "found expected c= argument");

	};
	my $E = $@;
	$tester->shutdown_servers;
	die $E if $E;
}
