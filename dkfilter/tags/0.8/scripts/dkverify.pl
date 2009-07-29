#!/usr/bin/perl -I../lib
#
# Copyright (c) 2005 Messiah College. This program is free software.
# You can redistribute it and/or modify it under the terms of the
# GNU Public License as found at http://www.fsf.org/copyleft/gpl.html.
#

use strict;
use warnings;

use Getopt::Long;
use DKMessage;

my $mess = DKMessage->new_from_handle(\*STDIN);
my $result = $mess->verify;
my $result_detail = $mess->result_detail;
print "$result_detail\n";
