#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use Mail::DomainKeys::Key::Private;

package Mail::DKIM::Algorithm::rsa_sha1;
use Carp;
use MIME::Base64;

sub new
{
	my $class = shift;
	my %args = @_;
	my $self = bless \%args, $class;
	$self->init;
	return $self;
}

sub init
{
	my $self = shift;

	$self->{buf} = "";
}

sub TIEHANDLE
{
	my $class = shift;
	return $class->new(@_);
}

sub PRINT
{
	my $self = shift;
	$self->{buf} .= join("", @_);
}

sub CLOSE
{
}

# Usage:
#   $b = $alg->sign($private_key);
#
sub sign
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($private_key) = @_;

	my $signature = $private_key->sign($self->{buf});
	return encode_base64($signature, "");
}

# Usage:
#   $result = $alg->verify($base64, $public_key);
#
sub verify
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 2);
	my ($base64, $public_key) = @_;

	my $sig = decode_base64($base64);
	return $public_key->verify(
			Text => $self->{buf},
			Signature => $sig);
}

1;

__END__

=head1 NAME

Mail::DKIM::Algorithm::rsa_sha1 - implements the rsa-sha1 signing algorithm for DKIM

=head1 BUGS

Currently, this implementation stores the entire canonicalized message
in memory in order to compute the SHA-1 hash. This should eventually be
changed to compute the SHA-1 hash incrementally so that a very large
message does not need to be stored in memory.

=cut
