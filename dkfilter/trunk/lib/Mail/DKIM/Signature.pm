#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use Mail::DKIM::PublicKey;

package Mail::DKIM::Signature;
use Carp;
our $VERSION = "0.18";

=head1 NAME

Mail::DKIM::Signature - encapsulates a DKIM signature header

=head1 CONSTRUCTORS

=head2 new() - create a new signature from parameters

  my $signature = new Mail::DKIM::Signature(
                      [ Algorithm => "rsa-sha1", ]
                      [ Signature => $base64, ]
                      [ Method => "nowsp", ]
                      [ Domain => "example.org", ]
                      [ Headers => "from:subject:date:message-id", ]
                      [ Query => "dns", ]
                      [ Selector => "alpha", ]
                  );

=cut

sub new {
	my $type = shift;
	my %prms = @_;
	my $self = {};

	$self->{'ALGO'} = $prms{'Algorithm'} || "rsa-sha1";
	$self->{'DATA'} = $prms{'Signature'};
	$self->{'METH'} = $prms{'Method'} || "simple";
	$self->{'DOMN'} = $prms{'Domain'};
	$self->{'HDRS'} = $prms{'Headers'};
	$self->{'PROT'} = $prms{'Query'} || "dns";
	$self->{'SLCT'} = $prms{'Selector'};

	bless $self, $type;
}

=head2 parse() - create a new signature from a DKIM-Signature header

  my $sig = parse Mail::DKIM::Signature(
                  "a=rsa-sha1; b=yluiJ7+0=; c=nowsp"
            );

Constructs a signature by parsing the provided DKIM-Signature header
content. Do not include the header name with the content.

Note: The input to this constructor is in the same format as the output
of the as_string method.

=cut

sub parse {
	my $type = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($string) = @_;

	my $self = {};

	foreach my $tag (split /;/, $string)
	{
		# strip preceding and trailing whitespace
		$tag =~ s/^\s*|\s*$//g;

		my ($tagname, $value) = split(/=/, $tag, 2);
		if ($tagname eq "a")
		{
			$self->{"ALGO"} = lc $value;
		}
		elsif ($tagname eq "b")
		{
			# remove whitespace
			$value =~ s/\s+//g;
			$self->{"DATA"} = $value;
		}
		elsif ($tagname eq "c")
		{
			$self->{"METH"} = lc $value;
		}
		elsif ($tagname eq "d")
		{
			$self->{"DOMN"} = lc $value;
		}
		elsif ($tagname eq "h")
		{
			# remove whitespace next to colons
			$value =~ s/\s+:/:/g;
			$value =~ s/:\s+/:/g;
			$self->{"HDRS"} = lc $value;
		}
		elsif ($tagname eq "i")
		{
			$self->{"i"} = $tagname;
		}
		elsif ($tagname eq "l")
		{
			$self->{"LEN"} = $value;
		}
		elsif ($tagname eq "q")
		{
			$self->{"PROT"} = lc $value;
		}
		elsif ($tagname eq "s")
		{
			$self->{"SLCT"} = $value;
		}
		elsif ($tagname eq "v")
		{
			die "detected forbidden v= tag";
		}
	}

	bless $self, $type;	
}

=head1 METHODS

=cut

sub wantheader {
	my $self = shift;
	my $attr = shift;

	$self->headerlist or
		return 1;
	
	foreach my $key ($self->headerlist) {
		lc $attr eq lc $key and
			return 1;
	}

	return;
}

=head2 as_string() - the signature encoded as a single string

  my $header = $signature->as_string;
  print "DKIM-Signature: $header\n";

As shown in the example, the as_string method can be used to generate
the DKIM-Signature that gets prepended to a signed message.

=cut

sub as_string {
	my $self = shift;

	my $text;


	$self->algorithm and
		$text .= "a=" . $self->algorithm . "; ";

	$self->headerlist and
		$text .= "h=" . $self->headerlist . "; ";

	$text .= "b=" . ($self->signature || "") . "; ";
	$text .= "c=" . $self->method . "; ";
	$text .= "d=" . $self->domain . "; ";
	$text .= "q=" . $self->protocol . "; ";
	$text .= "s=" . $self->selector;

	length $text and
		return $text;

	return;
}

=head2 as_string_without_data() - signature as a string, but not including the signature data

  my $header = $signature->as_string_without_data;

This is similar to the as_string() method, but it always excludes the "data"
part. This is used by the DKIM canonicalization methods, which require
incorporating this part of the signature into the signed message.

=cut

sub as_string_without_data
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 0);

	local $self->{DATA} = "";
	return $self->as_string;
}

sub sign {
	use MIME::Base64;

	my $self = shift;
	my %prms = @_;

	$self->method($prms{'Method'}) if $prms{'Method'};
	$self->selector($prms{'Selector'}) if $prms{'Selector'};
	$self->private($prms{'Private'}) if $prms{'Private'};

	my $text = $prms{'Text'} or
		$self->errorstr("no text given"),
		return;

	$self->method or
		$self->errorstr("no method specified"),
		return;

	$self->private or
		$self->errorstr("no private key specified"),
		return;

	$self->selector or
		$self->errorstr("no selector specified"),
		return;

	$self->domain or
		$self->errorstr("no domain specified"),
		return;

	$self->protocol or $self->protocol("dns");
	$self->algorithm or $self->algorithm("rsa-sha1");

	# FIXME: only needs to match the end of the domain
	#$prms{'Sender'}->host eq $self->domain or
	#	$self->errorstr("domain does not match address"),
	#	return;

	my $sign = $self->private->sign($text);
	my $signb64 = encode_base64($sign, "");

	$self->signature($signb64);

	$self->status("good");

	return 1;
}


use MIME::Base64;

sub get_public_key
{
	my $self = shift;

	unless ($self->public) {
		my $pubk = Mail::DKIM::PublicKey->fetch(
			Protocol => $self->protocol,
			Selector => $self->selector,
			Domain => $self->domain) or
				$self->status("no key"),
				$self->errorstr("no public key available"),
				return;

		$pubk->revoked and
			$self->status("revoked"),
			$self->errorstr("public key has been revoked"),
			return;

		$self->public($pubk);
	}
	return $self->public;
}

sub verify {

	my $self = shift;
	my %prms = @_;


	$self->status("bad format"),

	$self->protocol or
		$self->errorstr("no query protocol specified"),
		return;

	$self->selector or
		$self->errorstr("no selector specified"),
		return;

	$self->domain or
		$self->errorstr("no domain specified"),
		return;
	
	unless ($self->public) {
		my $pubk = fetch Mail::DomainKeys::Key::Public(
			Protocol => $self->protocol,
			Selector => $self->selector,
			Domain => $self->domain) or
				$self->status("no key"),
				$self->errorstr("no public key available"),
				return;

		$pubk->revoked and
			$self->status("revoked"),
			$self->errorstr("public key has been revoked"),
			return;

		$self->public($pubk);
	}

	$self->status("bad");

	# domain used in key should match domain of From: or Sender: header
	my $senderdomain = $prms{'Sender'}->host;
	my $keydomain = $self->domain;

	unless (lc($senderdomain) eq lc($keydomain) ||
		lc(substr($senderdomain, -(length($keydomain) + 1)))
			eq lc(".$keydomain"))
	{
		$self->errorstr("domain does not match address"),
		return;
	}

	$self->public->granularity and
		$prms{'Sender'}->user ne $self->public->granularity and
			$self->errorstr("granularity does not match address"),
			return;

	$self->public->verify(Text => $prms{'Text'},
		Signature => decode_base64($self->signature)) and
			$self->errorstr(undef),
			$self->status("good"),
			return 1;

	$self->errorstr("signature invalid");

	return;
}

sub algorithm {
	my $self = shift;

	(@_) and
		$self->{'ALGO'} = shift;

	$self->{'ALGO'};
}	

sub signature {
	my $self = shift;

	(@_) and
		$self->{'DATA'} = shift;

	$self->{'DATA'};
}	

=head2 domain() - get or set the domain of the signing entity

  my $d = $signature->domain;          # gets the domain value
  $signature->domain("example.org");   # sets the domain value

The domain of the signing entity, as specified in the signature.
This is the domain that will be queried for the public key.

=cut

sub domain
{
	my $self = shift;

	(@_) and
		$self->{'DOMN'} = shift;

	$self->{'DOMN'};
}	

sub errorstr {
	my $self = shift;

	(@_) and
		$self->{'ESTR'} = shift;

	$self->{'ESTR'};
}

sub headerlist {
	my $self = shift;

	(@_) and
		$self->{'HDRS'} = shift;

	if (wantarray and $self->{'HDRS'}) {
		my @list = split /:/, $self->{'HDRS'};
		@list = map { s/^\s+|\s+$//g; $_ } @list;
		return @list;
	}

	$self->{'HDRS'};
}	

sub method {
	my $self = shift;

	(@_) and
		$self->{'METH'} = shift;

	$self->{'METH'};
}	

sub public {
	my $self = shift;

	(@_) and
		$self->{'PBLC'} = shift;

	$self->{'PBLC'};
}
		
sub private {
	my $self = shift;

	(@_) and
		$self->{'PRIV'} = shift;

	$self->{'PRIV'};
}
		
sub protocol {
	my $self = shift;

	(@_) and
		$self->{'PROT'} = shift;

	$self->{'PROT'};
}	

sub selector {
	my $self = shift;

	(@_) and
		$self->{'SLCT'} = shift;

	$self->{'SLCT'};
}	

sub status {
	my $self = shift;

	(@_) and
		$self->{'STAT'} = shift;

	$self->{'STAT'};
}	

sub testing {
	my $self = shift;

	$self->public and $self->public->testing and
		return 1;

	return;
}

=head2 identity() - get or set the signing identity

  my $i = $signature->identity;

Identity of the user or agent on behalf of which this message is signed.
The identity has an optional local part, followed by "@", then a domain
name. The domain name should be the same as or a subdomain of the
domain returned by the C<domain> method.

Ideally, the identity should match the identity listed in the From:
header, or the Sender: header, but this is not required to have a
valid signature. Whether the identity used is "authorized" to sign
for the given message is not determined here.

=cut

sub identity
{
	my $self = shift;

	# set new identity if provided
	(@_) and
		$self->{'i'} = shift;

	if (defined $self->{"i"})
	{
		return $self->{"i"};
	}
	else
	{
		return '@' . $self->domain;
	}
}

=cut

1;
