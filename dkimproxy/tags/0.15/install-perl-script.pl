#-PERL

use strict;
use warnings;

my $INCLUDE = $ENV{"PERL_INCLUDE"};
my $PERL = $ENV{"PERL"};

die "missing PERL environment variable"
	unless ($PERL);
die "missing PERL_INCLUDE environment variable"
	unless ($INCLUDE);

die "wrong number of arguments\n"
	unless (@ARGV == 2);

my $source_filename = $ARGV[0];
my $dest_filename = $ARGV[1];

open my $source_fh, "<", $source_filename
	or die "can't read $source_filename: $!\n";

open my $dest_fh, ">", $dest_filename
	or die "can't write to $dest_filename: $!\n";

print $dest_fh "#!$PERL -I$INCLUDE\n";

while (my $line = <$source_fh>)
{
	next if ($line =~ m/^#!.*\/perl\b/);
	next if ($line =~ m/^use lib "\./);

	print $dest_fh $line;
}
