# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Mail::DomainKeys::Message;

use strict;
use Carp;

our $VERSION = "0.18";

sub load {
	use Mail::Address;
	use Mail::DomainKeys::Header;
	use Mail::DomainKeys::Signature;

	my $type = shift;
	my %prms = @_;

	my $self = {};


	my $file;

	if ($prms{'File'}) {
		if (ref $prms{'File'} and
			(ref $prms{'File'} eq "GLOB" or ref $prms{'File'} eq "IO::File")) {
			$file = $prms{'File'};
		} else {
			croak "wrong type " . ref($prms{"File"}) . " for File argument";
		}
	} else {
		$file = \*STDIN;
	}

	my $lnum = 0;

	my @head;

	if ($prms{'HeadString'}) {
		foreach (split /\n/, $prms{'HeadString'}) {
			s/\r$//;
			last if /^$/;
			if (/^\s/ and $head[$lnum-1]) {
				$head[$lnum-1]->append($_);
				next;
			}			
			$head[$lnum] =
				parse Mail::DomainKeys::Header(String => $_);

			$lnum++;
		}
	} else {
		while (<$file>) {
			s/\r$//;
			last if /^$/;
			if (/^\s/ and $head[$lnum-1]) {
				$head[$lnum-1]->append($_);
				next;
			}			
			$head[$lnum] =
				parse Mail::DomainKeys::Header(String => $_);

			$lnum++;
		}
	}

	my %seen = (FROM => 0, SIGN => 0, SNDR => 0);

	foreach my $hdr (@head) {
		# all headers after the DomainKeys-Signature header are "signed"
		$hdr->signed($seen{'SIGN'});

		$hdr->key or
			die "message parse error - invalid header\n";

		# TODO:
		#   signatures should be rejected if the header they are
		#   authenticating is not found after the signature
		#
		# TODO:
		#   duplicate From: headers or Sender: headers are illegal
		#   (AFAIK), so they should cause a signature failure if
		#   they are being used in the authentication process
		#
		if ($hdr->key =~ /^From$/i)
		{
			unless ($seen{'FROM'})
			{
				my @list = parse Mail::Address($hdr->vunfolded);
				$self->{'FROM'} = $list[0]; 
				$seen{'FROM'} = 1; 
			}
			else
			{
				# oops ... duplicate From: header
				warn "duplicate From: header";

				# TODO - do something about it
			}
		}
		elsif ($hdr->key =~ /^Sender$/i)
		{
			unless ($seen{'SNDR'})
			{
				my @list = parse Mail::Address($hdr->vunfolded);
				$self->{'SNDR'} = $list[0];
				$seen{'SNDR'} = 1;
			}
			else
			{
				# oops ... duplicate Sender: header
				warn "duplicate Sender: header";

				# TODO - do something about it
			}
		}
		elsif ($hdr->key =~ /^DomainKey-Signature$/i and not $seen{'SIGN'})
		{
			# found a DomainKey-Signature header
			$self->{'SIGN'} = parse Mail::DomainKeys::Signature(
				String => $hdr->vunfolded);
			$seen{'SIGN'} = 1;

			# check for already-parsed From: or Sender: header
			if ($seen{'SNDR'} || $seen{'FROM'})
			{
				# it appears there has been a From: or Sender: header
				# prepended to the message AFTER the signature was
				# generated, making the signature most likely invalid
				#
				# TODO - perhaps this signature should be ignored?
				# TODO - perhaps all signatures should be ignored?
				#
				# TODO - this doesn't handle the case where a mailing-list
				# added a Sender: header somewhere following the signature
				# header
			}
		}
	}

	my @body;

	if ($prms{'BodyReference'}) {
		@body = @{$prms{'BodyReference'}};
	} else {
		while (<$file>) {
			s/\r$//;
			push @body, $_;
		}
	}

	$self->{'HEAD'} = \@head;
	$self->{'BODY'} = \@body;

	bless $self, $type;
}

# $mess->gethline("From:Sender:Message-id:Subject:To");
#
# From the given headers, return a colon-separated list of headers that
# actually appear in the message, in the order they appear in the message,
# using the same capitalization as they appear in the message
#
sub gethline {
	my($self, $headers) = @_;

	return unless (defined $headers and length($headers));

	my %hmap = map { lc($_) => 1 } (split(/:/, $headers));

	my @found = ();
	foreach my $hdr (@{$self->head}) {
		if ($hmap{lc($hdr->key)}) {
			push(@found, $hdr->key);        
			delete $hmap{$hdr->key};
		}
	}

	my $res = join(':', @found);
	return $res;
}

sub header {
	my $self = shift;

	$self->signed or
		return new Mail::DomainKeys::Header(
			Line => "DomainKey-Status: no signature");

	$self->signature->status and
		return new Mail::DomainKeys::Header(
		Line => "DomainKey-Status: " . $self->signature->status);
}

sub nofws {	
	my $self = shift;
	my $signing = shift || 0;

	my $text = "";


	foreach my $hdr (@{$self->head}) {
		($hdr->signed || $signing) or
			next;
		$self->signature->wantheader($hdr->key) or
			next;
		my $line = $hdr->unfolded;
		$line =~ s/[\t\n\r\ ]//g;
		$text .= $line . "\r\n";
	}

	# delete trailing blank lines
	foreach (reverse @{$self->{'BODY'}}) {
		if (/^[\t\n\r\ ]*$/)
		{
			pop @{$self->{'BODY'}};
		}
		else
		{
			last;
		}
	}

	# make sure there is a body before adding a seperator line
	(scalar @{$self->{'BODY'}}) and
		$text .= "\r\n";

	foreach my $lin (@{$self->{'BODY'}}) {
		my $line = $lin;
		$line =~ s/[\t\n\r\ ]//g;
		$text .= $line . "\r\n";
	}

	return $text;
}

sub simple {
	my $self = shift;
	my $signing = shift || 0;

	my $text = "";


	foreach my $hdr (@{$self->head}) {
		($hdr->signed || $signing) or
			next;
		$self->signature->wantheader($hdr->key) or
			next;
		my $line = $hdr->line;
		# FIXME -- this won't work if the local line terminator does not end
		# with \n
		$line =~ s/\r*\n+/\015\012/g;
		$text .= $line;
	}

	# delete trailing blank lines
	foreach (reverse @{$self->{'BODY'}}) {
		/./ and
			last;
		/^$/ and
			pop @{$self->{'BODY'}};
	}

	# make sure there is a body before adding a seperator line
	(scalar @{$self->{'BODY'}}) and
		$text .= "\r\n";

	foreach my $lin (@{$self->{'BODY'}}) {
		my $line = $lin;
		# remove local line terminating characters; replace with CRLF
		$line =~ s/[\r\n]*$/\015\012/;
		$text .= $line;
	}

	return $text;
}

sub nowsp
{
	my $self = shift;
	my $signing = shift || 0;

	my $text = "";

	my @mess_headers = @{$self->head};
	foreach my $hdr_name ($self->signature->headerlist)
	{
		$hdr_name = lc $hdr_name;

		# find the specified header in the message
		internal_loop:
		for (my $i = 0; $i < @mess_headers; $i++)
		{
			if (lc($mess_headers[$i]->key) eq $hdr_name)
			{
				# found it
				my $hdr = $mess_headers[$i];

				# this removes it from our list, so if it occurs more than
				# once, we'll get the next header in line
				splice @mess_headers, $i, 1;

				my $line = $hdr->unfolded;

				# remove all whitespace
				$line =~ s/[\t\n\r\ ]//g;

				# map field name to lowercase
				$line =~ s/^([^:]+):/$hdr_name:/;

				$text .= $line . "\015\012";
				last internal_loop;
			}
		}
	}

	# delete trailing blank lines
	foreach (reverse @{$self->{'BODY'}}) {
		if (/^[\t\n\r\ ]*$/)
		{
			pop @{$self->{'BODY'}};
		}
		else
		{
			last;
		}
	}

	# make sure there is a body before adding a seperator line
	(scalar @{$self->{'BODY'}}) and
		$text .= "\r\n";

	foreach my $lin (@{$self->{'BODY'}}) {
		my $line = $lin;
		$line =~ s/[\t\n\r\ ]//g;
		$text .= $line;
	}

	# TODO - add the DKIM-Signature header (minus the b= tag)

	return $text;
}

sub sign {
	my $self = shift;
	my %prms = @_;

	if (not defined $prms{"Domain"})
	{
		$prms{"Domain"} = $self->senderdomain;
	}

	my $hline = $self->gethline($prms{'Headers'});

	my $sign = new Mail::DomainKeys::Signature(
		Method => $prms{'Method'},
		Domain => $prms{'Domain'},
		Headers => $hline,
		Selector => $prms{'Selector'});

	$self->signature($sign);

	my $canon = $sign->method eq "nofws" ? $self->nofws(1) :
				$sign->method eq "nowsp" ? $self->nowsp(1)
						: $self->simple(1);
	$sign->sign(Text => $canon, Private => $prms{'Private'});

	return $sign;
}

sub verify {
	my $self = shift;


	$self->signed or
		return;

	if (!$self->signature->method) {
		# method not defined
		return;
	}

	my $method = $self->signature->method;
	return $self->signature->verify(
			Text => ($method eq "nofws" ? $self->nofws :
					 $method eq "nowsp" ? $self->nowsp :
					 $method eq "simple" ? $self->simple :
					 die "unrecognized method\n"),
			Sender => ($self->sender or $self->from));
}

sub body {
	my $self = shift;

	(@_) and
		$self->{'BODY'} = shift;

	$self->{'BODY'};
}

sub from {
	my $self = shift;

	(@_) and
		$self->{'FROM'} = shift;

	$self->{'FROM'};
}

sub head {
	my $self = shift;

	(@_) and
		$self->{'HEAD'} = shift;

	$self->{'HEAD'}
}

sub sender {
	my $self = shift;

	(@_) and
		$self->{'SNDR'} = shift;

	$self->{'SNDR'};
}

sub senderdomain {
	my $self = shift;

	$self->sender and
		return $self->sender->host;

	$self->from and
		return $self->from->host;

	return;
}

sub signature {
	my $self = shift;

	(@_) and
		$self->{'SIGN'} = shift;

	$self->{'SIGN'};
}

sub signed {
	my $self = shift;

	$self->signature and
		return 1;

	return;
}

sub testing {
	my $self = shift;

	$self->signed and $self->signature->testing and
		return 1;

	return;
}

1;
