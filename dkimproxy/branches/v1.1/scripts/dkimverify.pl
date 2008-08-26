#!/usr/bin/perl -I../lib
#
# This file is part of DKIMproxy, an SMTP-proxy implementing DKIM.
# Copyright (c) 2005-2008 Messiah College.
# Written by Jason Long <jlong@messiah.edu>.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA  02110-1301, USA.
#

use strict;
use warnings;

use Mail::DKIM 0.17;
use Mail::DKIM::Verifier;
use Getopt::Long;

my $debug_canonicalization;
GetOptions(
		"debug-canonicalization=s" => \$debug_canonicalization,
		)
	or die "Error: invalid argument(s)\n";

my $dkim = new Mail::DKIM::Verifier(
		Debug_Canonicalization => $debug_canonicalization,
	);
while (<STDIN>)
{
	chomp;
	s/\015$//;
	$dkim->PRINT("$_\015\012");
}
$dkim->CLOSE;


print "originator address: " . $dkim->message_originator->address . "\n";
if ($dkim->signature)
{
	print "signature identity: " . $dkim->signature->identity . "\n";
}
print "verify result: " . $dkim->result_detail . "\n";

my $author_policy = $dkim->fetch_author_policy;
if ($author_policy)
{
	print "author policy result: " . $author_policy->apply($dkim) . "\n";
}
else
{
	print "author policy result: not found\n";
}
