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
