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
			croak "wrong type for File argument";
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
		$hdr->signed($seen{'SIGN'});

		$hdr->key or
			return;

		if ($hdr->key =~ /^From$/i and !$seen{'FROM'}) {
			my @list = parse Mail::Address($hdr->vunfolded);
			$self->{'FROM'} = $list[0]; 
			$seen{'FROM'} = 1; 
		} elsif ($hdr->key =~ /^Sender$/i and !$seen{'SNDR'}) {
			my @list = parse Mail::Address($hdr->vunfolded);
			$self->{'SNDR'} = $list[0];
			$seen{'SNDR'} = 1;
		} elsif ($hdr->key =~ /^DomainKey-Signature$/i and
			not $seen{'SIGN'}) {
			$self->{'SIGN'} = parse Mail::DomainKeys::Signature(
				String => $hdr->vunfolded);
			$seen{'SIGN'} = 1;
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

	my $text;


	foreach my $hdr (@{$self->head}) {
		($hdr->signed || $signing) or
			next;
		$self->signature->wantheader($hdr->key) or
			next;
		my $line = $hdr->unfolded;
		$line =~ s/[\t\n\r\ ]//g;
		$text .= $line . "\r\n";
	}

	# make sure there is a body before adding a seperator line
	(scalar @{$self->{'BODY'}}) and
		$text .= "\r\n";

	# delete trailing blank lines
	foreach (reverse @{$self->{'BODY'}}) {
		/./ and
			last;
		/^$/ and
			pop @{$self->{'BODY'}};
	}

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

	my $text;


	foreach my $hdr (@{$self->head}) {
		($hdr->signed || $signing) or
			next;
		$self->signature->wantheader($hdr->key) or
			next;
		my $line = $hdr->line;
		# $line =~ s/([^\r])\n/$1\r\n/g; # yuck
		#$line =~ s/([^\r])\n/$1\r\n/g; # yuck
		#chomp($line);
		$line =~ s/[\r\n]+//g;
		$text .= $line . "\r\n";
	}

	# make sure there is a body before adding a seperator line
	(scalar @{$self->{'BODY'}}) and
		$text .= "\r\n";

	# delete trailing blank lines
	foreach (reverse @{$self->{'BODY'}}) {
		/./ and
			last;
		/^$/ and
			pop @{$self->{'BODY'}};
	}

	foreach my $lin (@{$self->{'BODY'}}) {
		my $line = $lin;
		#$line eq "\n" and
		#	$line = "\r\n";
		#$line =~ s/([^\r])\n/$1\r\n/g; # yuck
		#$text .= $line;
		$line =~ s/[\r\n]+//g;
		$text .= $line . "\r\n";
	}

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

	my $canon= $sign->method eq "nofws" ? $self->nofws(1) : $self->simple(1);
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
	if ($self->signature->method eq "nofws") {
		return $self->signature->verify(Text => $self->nofws,
			Sender => ($self->sender or $self->from));
	} elsif ($self->signature->method eq "simple") {
		return $self->signature->verify(Text => $self->simple,
			Sender => ($self->sender or $self->from));
	} else {
		return;
	}

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
