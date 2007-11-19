use strict;
use warnings;

package AuthResults;

sub new
{
	my $class = shift;
	my $self = bless {}, $class;
	$self->version("1");

	{
		use Sys::Hostname;
		$self->host( hostname() );
	}
	$self->{Results} = [];

	return $self;
}

sub as_string
{
	my $self = shift;

	my $result = "Authentication-Results: " . $self->host;
	if (my $v = $self->version)
	{
		$result .= " version=$v";
	}
	foreach my $result_spec ($self->results)
	{
		$result .= "; " . $self->result_as_string($result_spec);
	}
	return $result;
}

sub host
{
	my $self = shift;
	@_ and
		$self->{Host} = shift;
	return $self->{Host};
}

sub results
{
	my $self = shift;
	return @{$self->{Results}};
}

sub append_result
{
	my $self = shift;
	my %args = @_;
	push @{$self->{Results}}, \%args;
}

sub result_as_string
{
	my $self = shift;
	my $result_spec = shift;

	return $result_spec->{Method} . "=" . $result_spec->{Result}
		. ($result_spec->{Comment} ? (" (" . $result_spec->{Comment} . ")") : "")
		. join("",
			map { " " . $_->[0] . "=" . $_->[1] }
				@{$result_spec->{Specifiers}}
			);
}

sub version
{
	my $self = shift;
	@_ and
		$self->{Version} = shift;
	return $self->{Version};
}

1;

__END__

=head1 BUGS

This module should have the capability of parsing
Authentication-Results headers and extracting the useful information
out of them. I need to take time to consider what sorts of results
will be useful.

For instance, if I was an MUA, what information will I want to
know from this header?

=over

=item 1.

can this header be trusted... i.e. was it added my a trusted
mail server, or was it part of the original untrusted message

=item 2.

which identities in the header (i.e. the "From" address,
the "Sender" address, other addresses) can be trusted,
and what methods were used to verify

E.g. maybe a UI like this

  From: Jason Long <jlong@messiah.edu>    ** DKIM VERIFIED **
  Sender: George <george@example.com>     not verified
  Return-Path: George <george@example.com> ** SPF VERIFIED **

=back

=cut
