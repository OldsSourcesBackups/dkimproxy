use strict;
use warnings;

package LookupMap;

sub load
{
	my $class = shift;
	my ($mapfile) = @_;

	unless (-f $mapfile)
	{
		die "Error: $mapfile: file not found\n";
	}

	my $self = bless { file => $mapfile }, $class;
	return $self;
}

# lookup_address() - find an address in a map file
#
# the address is an email address. this function looks first for
# the full email address, and if not found, tries more and more
# general forms of the email addresses
#
# returns ($result, $key)
# where $result is the right-hand value found in the map
# and $key is the left-hand key corresponding to the found value
# (a derivative of $address)
#
sub lookup_address
{
	my $self = shift;
	my ($address) = @_;

	$address = lc $address;
	my @lookup_keys = ($address);

	if ($address =~ s/\+(.*)\@//)
	{
		# local part of address has a extension, lookup same
		# address without extension
		# e.g. jason+extra@long.name => jason@long.name
		push @lookup_keys, $address;
	}

	if ($address =~ s/^(.*)\@//)
	{
		# lookup just the domain of the address
		push @lookup_keys, $address;
	}
	while ($address =~ s/^([^.]+\.)//)
	{
		# domain has at least two parts, try again with
		# the first part removed
		push @lookup_keys, $address;
	}
	# a catch-all key
	push @lookup_keys, ".";

	return $self->lookup(\@lookup_keys);
}

sub lookup
{
	my $self = shift;
	my ($keys_arrayref) = @_;

	my $best_idx = @$keys_arrayref;
	my $best_result;

	open my $fh, "<", $self->{file}
		or die "Error: cannot read $self->{file}: $!\n";
	while (<$fh>)
	{
		chomp;
		next if /^\s*$/;
		next if /^\s*[#;]/;
		if (/^(\S+)\s+(.*)$/)
		{
			for (my $i = 0; $i < $best_idx; $i++)
			{
				if ($1 eq $keys_arrayref->[$i])
				{
					$best_idx = $i;
					$best_result = $2;
				}
			}
		}
	}
	close $fh;
	return ($best_result, $keys_arrayref->[$best_idx]);
}

1;
