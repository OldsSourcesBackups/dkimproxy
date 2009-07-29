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

	my $mess = Mail::DomainKeys::Message->load(File => $handle)
		or die "message parse error\n";
	my $self = {
		fh => $handle,
		mess => $mess
		};
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
	if (lc($senderdomain) ne lc($domain) &&
		lc(substr($senderdomain, -(length($domain) + 1))) ne lc(".$domain"))
	{
		$self->set_sign_result(
			"skipped", "wrong sender domain");
		return "skipped";
	}

	# determine headers to use
	my @headers;
	if ($prms{Headers})
	{
		# add all headers found in the message
		foreach my $found_hdr (@{$mess->head})
		{
			push @headers, $found_hdr->key;
		}
	}

	# TODO - check for existing DomainKey-Signature header. If present,
	# a new signature should only be added if a Sender header has been
	# added and it was not part of the original signature (i.e. a
	# mailing list message)

	my $sign = $mess->sign(
		Method => $prms{Method},
		Selector => $prms{Selector},
		Domain => $domain,
		Headers => join(":", @headers),
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

	# catch errors
	eval
	{
		# perform verification
		my ($result, $detail) = $self->do_verify(%policy);

		# set/return the result
		$self->set_verify_result($result, $detail);
		return $result;
	};
	if ($@)
	{
		# error occurred
		my $E = $@;
		chomp $E;

		# set/return the result
		$self->set_verify_result("temperror", $E);
		return "temperror";
	}
}

sub do_verify
{
	my $self = shift;
	my %policy = @_;

	my $mess = $self->mess;

	# no sender domain means no verification 
	unless ($mess->senderdomain)
	{
		return ("neutral", "unable to determine sender domain");
	}

	if ($mess->signed && $mess->verify)
	{
		# message is signed, and verification succeeded...
		return ("pass");
	}

	my $signature_problem;
	if ($mess->signed)
	{
		# signature is invalid
		$signature_problem = $mess->signature->errorstr;
	}
	else
	{
		$signature_problem = "no signature";
	}

	# FIXME - policy domain should be determined by signature, not the
	# from/sender header... of course the signature should be checked that
	# it matches the from/sender header
	#
	my $policydomain = $mess->senderdomain;

	# unverified or not signed: check for a domain policy
	my $plcy = Mail::DomainKeys::Policy->fetch(
		Protocol => "dns",
		Domain => $policydomain);
	unless ($plcy)
	{
		# no policy
		return ("neutral",
			"$signature_problem; no policy for $policydomain");
	}

	# domain or key testing: add header and return
	if ($mess->testing)
	{
		return ("neutral",
			"$signature_problem; key testing");
	}
	if ($plcy->testing)
	{
		return ("neutral",
			"$signature_problem; domain testing");
	}
	
	# not signed and domain doesn't sign all
	if ($plcy->signsome && !$mess->signed)
	{
		return ("softfail",
			"$signature_problem; not needed for $policydomain");
	}

	# last check to see if policy requires all mail to be signed
	unless ($plcy->signall)
	{
		return ("softfail",
			"$signature_problem; not required for $policydomain");
	}

	# should be correctly signed and it isn't: reject
	return ("fail", $signature_problem);
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

sub senderdomain
{
	my $self = shift;
	return $self->mess->senderdomain;
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
__END__

=head1 NAME

DKMessage - signs and verifies DomainKeys

=head1 SYNOPSIS

  $fh = IO::File->new("<message.in");
  $mess = DKMessage->new_from_handle($fh);

  # verify the DomainKeys-Signature in $mess
  $result = $mess->verify;

  # or, sign the message in $mess
  $result = $mess->sign;

  # print out the modified message
  $fh->seek(0, 0);
  while (my $line = $mess->readline)
  {
      print $line;
  }

=head1 DESCRIPTION

=over

=item DKMessage->new_from_handle

Reads a message and gets ready to sign or verify it.

  my $mess = DKMessage->new_from_handle($file_handle);

=item $mess->sign

Signs the message. You must provide a few parameters...

  $result = $mess->sign(
              Method => $method,
              Selector => $selector,
              Domain => $domain,
              KeyFile => $keyfile,
              [Headers => 1,]
            );

The B<Method> argument determines the canonicalization method, either
C<simple> or C<nofws>.

The B<Selector> argument specifies the name of the key being used to
sign the message. This name is included in the resulting header and is
used on the verifying end to lookup the public key in DNS.

The B<Domain> argument specifies what domain is being signed for. It
should match the domain in the Sender: or From: header.

The B<KeyFile> argument is the filename of the file containing the private
key used in signing the message.

The optional B<Headers> argument specifies whether or not to generate a
C<h> tag for the DomainKey-Signature header. If a nonzero value is specified,
an C<h> tag is generated containing all header field names found in the email.
Otherwise, no C<h> tag is generated.

The return value will be a string, either "signed" if the message was
successfully signed, or "skipped" if no signature can be added.

=item $mess->verify

Verifies the signature contained in $mess.

  $result = $mess->verify;

The return value is one of "neutral", "pass", "fail", or "softfail".
B<neutral> means no signature found.
B<pass> means the message has a valid signature.
B<fail> means the message has an invalid or missing signature,
and the sending domain signs all messages.
B<softfail> means the message has an invalid or missing signature,
and the sending domain signs at least some messages.

=item $mess->result_detail

Provides additional information about the result of the last operation
(sign or verify).

  $result_detail = $mess->result_detail;

The return value of B<result_detail> is a human-readable string containing
the result and possibly a short phrase describing the result.

E.g. for result=neutral, the B<result_detail> method might return
"neutral (no signature)", or for result=fail, it might return
"fail (public key has been revoked)".

=item $mess->info;

Returns a list of message attributes helpful for identifying the message.

  @info = $mess->info;
  print join(", ", @info), "\n";

This method is meant for helping to log singing and verifying results
in the system log. By joining the results of this list together like
above, you can get something like this:

  from=<john.doe@example.org>, message-id=<39842729042@example.org>

=item $mess->senderdomain

Returns the domain part of the address that should be verified or signed
for (either in From: header or Sender: header). If neither header is
available, returns C<undef>.

=item $mess->readline

After signing or verifying a message, use this to read back the modified
message.

  while (my $line = $mess->readline)
  {
      print $line;
  }

Each line returned from B<readline> includes line termination characters
(e.g. "\015\012"), so you do not need to transmit them for each line.
The purpose of this method is to allow access to the modified message
without requiring the entire message in memory.

=back

=head1 AUTHOR

Jason Long - jlong@messiah.edu

=head1 SEE ALSO

See the documentation for smtpprox and Mail::DomainKeys. And of course,
http://antispam.yahoo.com/domainkeys

=head1 COPYRIGHT and LICENSE

Copyright (c) 2005 Messiah College. This file is original work. It can
be redistributed under the same terms as Perl itself.

=cut
