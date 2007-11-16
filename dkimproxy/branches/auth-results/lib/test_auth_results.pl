#!/usr/bin/perl
#

use strict;
use warnings;

use AuthResults;

my $auth_results = AuthResults->new;
print $auth_results->as_string . "\n";
