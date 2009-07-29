#!/usr/bin/perl
#
# Copyright (c) 2005 Messiah College. This program is free software.
# You can redistribute it and/or modify it under the terms of the
# GNU Public License as found at http://www.fsf.org/copyleft/gpl.html.
#

use strict;
use warnings;

package DKMessage;
use Mail::DomainKeys::Message;
use Mail::DomainKeys::Policy;
use Mail::DomainKeys::Key::Private;
use Carp;

my $hostname;
use Sys::Hostname;
$hostname = hostname;

sub new_from_handle
{
	my $class = shift;
	my ($handle) = @_;

	my $self = {
		fh => $handle,
		mess => Mail::DomainKeys::Message->load(File => $handle)
		};
	unless (defined $self->{mess})
	{
		die "message parse error";
	}
	return bless $self, $class;
}

sub use_hostname
{
	$hostname = shift;
}

sub mess
{
	my $self = shift;
	return $self->{"mess"};
}

sub sign
{
	my $self = shift;
	my %prms = @_;

	if ($self->{verify_result})
	{
		die "can't sign a message that I already verified";
	}

	# check for missing arguments
	croak "missing Domain argument" unless ($prms{Domain});
	croak "missing KeyFile argument" unless ($prms{KeyFile});

	my $domain = $prms{Domain};

	my $mess = $self->mess;
	my $senderdomain = $mess->senderdomain;

	# confirm that senderdomain ends with given header
	if (not defined $senderdomain)
	{
		$self->set_sign_result(
			"skipped", "no sender/from header");
		return "skipped";
	}
	if ($senderdomain ne $domain &&
		substr($senderdomain, -(length($domain) + 1)) ne ".$domain")
	{
		$self->set_sign_result(
			"skipped", "wrong sender domain");
		return "skipped";
	}

	my $sign = $mess->sign(
		Method => $prms{Method},
		Selector => $prms{Selector},
		Domain => $domain,
		Private =>
			Mail::DomainKeys::Key::Private->load(
				File => $prms{KeyFile})
		);
	if ($sign)
	{
		$self->set_sign_result("signed");
		$self->{sign} = $sign;
		return "signed";
	}
	die "sign failed";
}

sub verify
{
	my $self = shift;
	my %policy = @_;

	if ($self->{sign_result})
	{
		die "can't verify a message that I already signed";
	}

	my $mess = $self->mess;

	# no sender domain means no verification 
	unless ($mess->senderdomain)
	{
		$self->set_verify_result(
			"neutral", "unable to determine sender domain");
		return "neutral";
	}

	if ($mess->signed && $mess->verify)
	{
		# message is signed, and verification succeeded...
		$self->set_verify_result("pass");
		return "pass";
	}

	# unverified or not signed: check for a domain policy
	my $senderdomain = $mess->senderdomain;
	my $plcy = Mail::DomainKeys::Policy->fetch(
		Protocol => "dns",
		Domain => $senderdomain);
	unless ($plcy)
	{
		# no policy
		$self->set_verify_result("neutral",
			$mess->signed ? "signature failed, but no policy"
				: "no signature");
		return "neutral";
	}

	# not signed and domain doesn't sign all
	if ($plcy->signsome && !$mess->signed)
	{
		$self->set_verify_result("softfail", "no signature");
		return "softfail";
	}

	# domain or key testing: add header and return
	if ($mess->testing)
	{
		$self->set_verify_result("softfail", "key testing");
		return "softfail";
	}
	if ($plcy->testing)
	{
		$self->set_verify_result("softfail", "domain testing");
		return "softfail";
	}
	
	# last check to see if policy requires all mail to be signed
	unless ($plcy->signall)
	{
		$self->set_verify_result("softfail", "not required by policy");
		return "softfail";
	}

	# should be correctly signed and it isn't: reject
	$self->set_verify_result("fail",
			$mess->signed ? "invalid signature" : "no signature");
	return "fail";
}

sub set_sign_result
{
	my $self = shift;
	my ($result, $detail) = @_;

	$self->{sign_result} = $result;
	if ($detail)
	{
		$self->{sign_result} .= " ($detail)";
	}
}

sub set_verify_result
{
	my $self = shift;
	my ($result, $detail) = @_;

	$self->{verify_result} = $result;
	if ($detail)
	{
		$self->{verify_result} .= " ($detail)";
	}
}

sub result_detail
{
	my $self = shift;

	return $self->{verify_result} || $self->{sign_result};
}

#
# Usage: ($header, $mailbox) = $mess->headerspec;
#
sub headerspec
{
	my $self = shift;

	if ($self->mess->sender)
	{
		return ("sender", $self->mess->sender->address);
	}
	elsif ($self->mess->from)
	{
		return ("from", $self->mess->from->address);
	}
	return ();
}

sub message_id
{
	my $self = shift;

	# try to determine message-id header
	foreach my $hdr (@{$self->mess->head})
	{
		if ($hdr->key =~ /^Message-Id$/i)
		{
			my $result = $hdr->vunfolded;
			$result =~ s/^\s*<//;
			$result =~ s/>\s*$//;
			return $result;
		}
	}
	return undef;
}

sub info
{
	my $self = shift;
	my @info;

	my ($header, $mailbox) = $self->headerspec;
	if ($header)
	{
		push @info, "$header=<$mailbox>";
	}

	my $message_id = $self->message_id;
	if (defined $message_id)
	{
		push @info, "message-id=<$message_id>";
	}
	return @info;
}

sub readline
{
	my $self = shift;
	my $fh = $self->{fh};

	if ($self->{sign})
	{
		my $result = $self->signature_header . "\015\012";
		delete $self->{sign};
		return $result;
	}
	if ($self->{verify_result})
	{
		my $result = $self->auth_header . "\015\012";
		delete $self->{verify_result};
		$self->{in_untrusted_headers} = 1;
		return $result;
	}

	if ($self->{in_untrusted_headers})
	{
		# if any "Authentication-Results:" headers are found before the
		# signature, skip them
		local $_;
		local $/ = "\015\012";
		while (<$fh>)
		{
			# FIXME - shouldn't remove authentication-results header
			# if it specifies a different server name 
			if (/^Authentication-Results\s*:/i || /^DomainKey-Status\s*:/i)
			{
				# skip this header and any folding lines it has
				while (<$fh>)
				{
					last unless (/^\s/);
				}
			}
			if (/^$/ || /^DomainKey-Signature:/i)
			{
				$self->{in_untrusted_headers} = 0;
			}

			return $_;
		}
		return undef;
	}
	else
	{
		local $_;
		local $/ = "\015\012";
		return <$fh>;
	}
}

sub auth_header
{
	my $self = shift;

	my $header = "Authentication-Results: $hostname";
	my @headerspec = $self->headerspec;
	if (@headerspec)
	{
		$header .= " $headerspec[0]=$headerspec[1]";
	}

	return "$header; domainkey="
		. $self->result_detail;
}

sub signature_header
{
	my $self = shift;
	my $sign = $self->{sign};

	if (not defined $sign)
	{
		die "message has not been signed";
	}

	return "DomainKey-Signature: " . $sign->as_string;
}


1;
