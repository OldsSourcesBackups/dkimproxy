use strict;
use warnings;

package LookupMap;

=head1 NAME

LookupMap - query a Dkimproxy-compatible lookup table

=head1 SYNOPSIS

  my $map = LookupMap->load("/path/to/mapfile");
  my $result = $map->lookup(
=head1 CONSTRUCTOR

=head2 load() - load a lookup table

  my $map = LookupMap->load("/path/to/mapfile");
  my $result = $map->lookup_address('bob@example.org');

=cut

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

=head1 METHODS

=head2 lookup_address() - find an address in a map file

  my ($result, $key) = $map->lookup_address('bob@example.com');

The address is an email address. this function looks first for
the full email address, and if not found, tries more and more
general forms of the email addresses

The result is a two element list. The first element is the result
found in the map. The second element is the key by which the value
was found. E.g. if you looked up bob@example.com but the map only
had an entry for example.com, the key would be example.com.

=cut

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

=head2 lookup() - lookup a raw value in the map file

  my $result = $map->lookup('10.20.30.40');
  my ($result, $key) = $map->lookup([ '10.20.30.40', '10.20.30', '10.20', '10' ]);

=cut

sub lookup
{
	my $self = shift;
	my ($keys_arrayref) = @_;

	$keys_arrayref = [ $keys_arrayref ] if not ref $keys_arrayref;

	my $map = $self->read_map();

	foreach my $key (@$keys_arrayref)
	{
		my $result = $map->{$key};
		if (defined $result)
		{
			if (wantarray)
			{
				return ($result, $key);
			}
			else
			{
				return $result;
			}
		}
	}
	return;
}

# read_map() - private function - reads the map file into memory
#
# this function loads the map file and reads it into a hash.
# to avoid having to reread the entire file every time, it
# saves the contents of the map in memory, and on subsequent
# calls, it compares the mtime of the file with that in memory
#
sub read_map
{
	my $self = shift;

	open my $fh, "<", $self->{file}
		or die "Error: cannot read $self->{file}: $!\n";
	my $map_mtime = (stat $fh)[9];

	# FIXME- if the file is changed multiple times in the same second,
	# then we may be caching an old version of the file
	#
	if (!$self->{cached}
		|| $map_mtime > $self->{cached_mtime})
	{
		my $map = {};
		while (<$fh>)
		{
			chomp;
			next if /^\s*$/;
			next if /^\s*[#;]/;
			if (/^(\S+)\s+(.*)$/)
			{
				$map->{$1} = $2;
			}
		}
		$self->{cached} = $map;
		$self->{cached_mtime} = $map_mtime;
	}
	close $fh;

	return $self->{cached};
}

1;
