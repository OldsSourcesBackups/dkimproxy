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
		'--signature=dkim(d=$senderdomain,i=$sender)',
		];
	$tester->start_servers;

	my @signatures;
	eval {

	@signatures = $tester->generate_signatures("msg4.txt");
	ok(@signatures == 1, "should be one signature");
	print "# " . $signatures[0]->as_string . "\n";
	ok($signatures[0]->domain eq "foo.domain3.example", "found expected d= argument");
	ok($signatures[0]->identity eq 'smith@foo.domain3.example', "found expected i= argument");
	
	};
	my $E = $@;
	$tester->shutdown_servers;
	die $E if $E;
}

{
	$tester->{proxy_args} = [
		"--keyfile=/tmp/private.key",
		"--selector=s1",
		"--method=relaxed",
		'--signature=dkim(d=$senderdomain,i=$sender)',
		];
	$tester->start_servers;

	my @signatures;
	eval {

	@signatures = $tester->generate_signatures("msg1.txt");
	ok(@signatures == 1, "should be one signature");
	print "# " . $signatures[0]->as_string . "\n";
	ok($signatures[0]->domain eq "domain1.example", "found expected d= argument");
	ok($signatures[0]->identity eq 'jlong@domain1.example', "found expected i= argument");
	
	@signatures = $tester->generate_signatures("msg2.txt");
	ok(@signatures == 1, "should be one signature");
	print "# " . $signatures[0]->as_string . "\n";
	ok($signatures[0]->domain eq "domain2.example", "found expected d= argument");
	ok($signatures[0]->identity eq 'jlong@domain2.example', "found expected i= argument");
	};
	my $E = $@;
	$tester->shutdown_servers;
	die $E if $E;
}


