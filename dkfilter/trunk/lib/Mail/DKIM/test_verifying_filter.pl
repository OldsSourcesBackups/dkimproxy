#!/usr/bin/perl -I../..

use strict;
use warnings;

use Mail::DKIM::Verifier;

my $filter = Mail::DKIM::Verifier->new_object();
while (<STDIN>)
{
	chomp;
	s/\015$//;
	$filter->PRINT("$_\015\012");
}
$filter->CLOSE;


print "result = " . $filter->result . "\n";
print "originator address = " . $filter->message_originator->address . "\n";
print "sender address = " . $filter->message_sender->address . "\n";
print "signature identity = " . $filter->signature->identity . "\n";
print "message id = " . $filter->message_id . "\n"
	if (defined $filter->message_id);
