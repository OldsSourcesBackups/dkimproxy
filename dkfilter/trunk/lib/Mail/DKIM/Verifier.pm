#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use Mail::DKIM::Canonicalization::nowsp;
use Mail::DKIM::Algorithm::rsa_sha1;
use Mail::DKIM::Signature;
use Mail::Address;

=head1 NAME

Mail::DKIM::Verifier - verifies a DKIM-signed message

=head1 SYNOPSIS

  use Mail::DKIM::Verifier;

  # create a verifier object
  my $dkim = Mail::DKIM::Verifier->new_object();

  # read an email from stdin, pass it into the verifier
  while (<STDIN>)
  {
      # remove local line terminators
      chomp;
      s/\015$//;

      # use SMTP line terminators
      $dkim->PRINT("$_\015\012");
  }
  $dkim->CLOSE;

  # what is the result of the verify?
  my $result = $dkim->result;

=head1 CONSTRUCTOR

=head2 new_object() - construct an object-oriented verifier

  my $dkim = Mail::DKIM::Verifier->new_object();

=cut

package Mail::DKIM::Verifier;
use base "Mail::DKIM::Common";
use Carp;

# sub init
# {
# 	my $self = shift;
# 	$self->SUPER::init;
# }

sub handle_header
{
	my $self = shift;
	my ($field_name, $contents) = @_;

	$self->SUPER::handle_header($field_name, $contents);

	if (lc($field_name) eq "dkim-signature")
	{
		$self->add_signature($contents);
	}
}

sub add_signature
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($contents) = @_;

	my $signature = Mail::DKIM::Signature->parse($contents);
	push @{$self->{signatures}}, $signature;
}

sub check_signature
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($signature) = @_;

	if ($signature->algorithm ne "rsa-sha1")
	{
		# unsupported algorithm
		$self->{signature_reject_reason} = "unsupported algorithm";
		return 0;
	}

	if ($signature->method ne "nowsp" &&
		$signature->method ne "simple")
	{
		# unsupported canonicalization method
		$self->{signature_reject_reason} = "unsupported canonicalization";
		return 0;
	}

	if ($signature->protocol ne "dns")
	{
		# unsupported protocol
		$self->{signature_reject_reason} = "unsupported protocol";
		return 0;
	}

	# check domain
	my $responsible_address = $self->get_responsible_address;
	if (!$responsible_address)
	{
		# oops, no From: or Sender: header
		die "No From: or Sender: header";
	}

	my $senderdomain = $responsible_address->host;
	my $sigdomain = $signature->domain;
	if (!$self->match_subdomain($senderdomain, $sigdomain))
	{
		$self->{signature_reject_reason} = "unmatched domain";
		return 0;
	}

	return 1;
}

sub match_subdomain
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 2);
	my ($subdomain, $superdomain) = @_;

	my $tmp = substr(".$subdomain", -1 - length($superdomain));
	return (".$superdomain" eq $tmp);
}

#
# called when the verifier has received the last of the message headers
# (body is still to come)
#
sub finish_header
{
	my $self = shift;

	# The message may have contained zero, one, or multiple signatures.
	# In the case of multiple signatures, we need to loop through each
	# one, finding one that we can use to verify.

	$self->{signature} = undef;
	foreach my $signature (@{$self->{signatures}})
	{
		next unless ($self->check_signature($signature));

		# get public key
		$self->{public_key} = $signature->get_public_key;
		unless ($self->{public_key})
		{
			# public key not available
			$self->{signature_reject_reason} = "public key not available";
			next;
		}

		# this signature is ok
		$self->{signature} = $signature;
		last;
	}

	unless ($self->{signature})
	{
		# FIXME
		my $reason = $self->{signature_reject_reason} || "";
		die "no valid signature found - $reason\n";
	}

	# create a canonicalization filter and algorithm
	my $algorithm_class = $self->get_algorithm_class(
				$self->{signature}->algorithm);
	local *alg_fh;
	tie *alg_fh, $algorithm_class;
	$self->{algorithm} = tied *alg_fh;

	my $canon_class = $self->get_canonicalization_class(
				$self->{signature}->method);
	my $canon = $canon_class->new(
				output_fh => *alg_fh,
				Signature => $self->{signature});

	# output header as received so far into canonicalization
	foreach my $line (@{$self->{headers}})
	{
		$canon->PRINT($line);
	}
	$canon->PRINT("\015\012");

	$self->{canon} = $canon;
}

sub finish_body
{
	my $self = shift;

	# finished canonicalizing
	$self->{canon}->CLOSE;

	if ($self->{public_key})
	{
		# verify signature
		my $signb64 = $self->{signature}->signature;
		my $verify_result = $self->{algorithm}->verify($signb64,
		                                               $self->{public_key});
		$self->{result} = $verify_result ? "pass" : "failed validation";
	}
	else
	{
		$self->{result} = "failed to get public key";
	}
}

=head1 METHODS

=head2 PRINT() - feed part of the message to the verifier

  $dkim->PRINT("a line of the message\015\012");

Feeds content of the message being verified into the verifier.
The API is designed this way so that the entire message does NOT need
to be read into memory at once.

=head2 CLOSE() - call this when finished feeding in the message

  $dkim->CLOSE;

This method finishes the canonicalization process, computes a hash,
and verifies the signature.

=head2 load() - load the entire message from a file handle

  $dkim->load($file_handle);

Reads a complete message from the designated file handle,
feeding it into the signer.

=head2 message_originator() - access the "From" header

  my $address = $dkim->message_originator;

Returns the "originator address" found in the message. This is typically
the (first) name and email address found in the From: header. The returned
object is of type Mail::Address. To get just the email address part, do:

  my $email = $dkim->message_originator->address;

=cut


# deprecated...
sub get_responsible_address
{
	my $self = shift;
	return $self->message_originator(@_);
}

=head2 message_sender() - access the "From" or "Sender" header

  my $address = $dkim->message_sender;

Returns the "sender" found in the message. This is typically the (first)
name and email address found in the Sender: header. If there is no Sender:
header, it is the first name and email address in the From: header.
The returned object is of type Mail::Address, so to get just the email
address part, do:

  my $email = $dkim->message_sender->address;

This method does not correspond directly to the DKIM spec, but it seems
useful when signing an outbound message to sign based on "sender."


=head2 result() - access the result of the verification

  my $result = $dkim->result;

Gives the result of the verification. If the verify was successful, this
will be "pass".

=cut

=head2 signature() - access the message's DKIM signature

  my $sig = $dkim->signature;

Accesses the signature found and verified in this message. The returned
object is of type Mail::DKIM::Signature.

=cut

sub signature
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 0);
	return $self->{signature};
}

1;
