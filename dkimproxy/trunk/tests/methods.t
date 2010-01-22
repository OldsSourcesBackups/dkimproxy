#!/usr/bin/perl

use strict;
use warnings;

use TestHarnass;
use Test::More tests => 21;

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
		"--domain=domain1.example",
		"--keyfile=/tmp/private.key",
		"--selector=s1",
		];
	$tester->start_servers;

	my @signatures;
	eval {

	@signatures = $tester->generate_signatures("msg1.txt");
	ok(@signatures == 1, "should be one signature");
	print "# " . $signatures[0]->as_string . "\n";
	ok($signatures[0]->domain eq "domain1.example", "found expected d= argument");
	ok($signatures[0]->method eq "relaxed", "found expected c= argument");

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
		"--dkim_method=relaxed",
		"--domainkeys_method=nofws",
		"--signature=dkim",
		"--signature=domainkeys",
		"--method=foo",
		];
	$tester->start_servers;

	my @signatures;
	eval {

	@signatures = $tester->generate_signatures("msg1.txt");
	ok(@signatures == 2, "should be two signatures");
	my $sig_text = $signatures[0]->as_string;
	print "# $sig_text\n";
	ok($sig_text =~ /^DKIM-Signature/, "found DKIM signature");
	ok($sig_text =~ /c=relaxed/, "found expected c= argument");
	$sig_text = $signatures[1]->as_string;
	print "# $sig_text\n";
	ok($sig_text =~ /^DomainKey-Signature/, "found DKIM signature");
	ok($sig_text =~ /c=nofws/, "found expected c= argument");
	print "# " . $signatures[1]->as_string . "\n";
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

SKIP: {
	#TODO- test that the proxy fails to start up if a bad method name
	#is specified
	skip "cannot test for failed startup yet", 1;

	$tester->{proxy_args} = [
		"--domain=domain1.example",
		"--keyfile=/tmp/private.key",
		"--selector=s1",
		"--method=foo",
		];
	$tester->start_servers;

	my @signatures;
	eval {
		ok(0);
	};
	my $E = $@;
	$tester->shutdown_servers;
	die $E if $E;
}

