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
		$self->{host} = shift;
	return $self->{host};
}

sub version
{
	my $self = shift;
	@_ and
		$self->{version} = shift;
	return $self->{version};
}

1;
