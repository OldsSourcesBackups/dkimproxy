#!/usr/bin/perl
#

use strict;
use warnings;

use AuthResults;

my $auth_results = AuthResults->new;
print $auth_results->as_string . "\n";

$auth_results->host("host.example.com");
print $auth_results->as_string . "\n";

$auth_results->append_result(
	Method => "dkim",
	Result => "pass",
	Comment => "with flying colors",
	Specifiers => [ [ "header.i" => "foo\@example.com" ] ],
	);
print $auth_results->as_string . "\n";

push @{$auth_results->{Results}->[0]->{Specifiers}},
	[ "header.sender" => "foo\@example.com" ];
print $auth_results->as_string . "\n";

$auth_results->append_result(
	Method => "spf",
	Result => "softfail",
	Specifiers => [ [ "smtp.from" => "nobody\@dev.null" ] ],
	);
print $auth_results->as_string . "\n";
