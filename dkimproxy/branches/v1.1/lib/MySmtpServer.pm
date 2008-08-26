#!/usr/bin/perl
#
# This file is part of DKIMproxy, an SMTP-proxy implementing DKIM.
# Copyright (c) 2005-2008 Messiah College.
# Written by Jason Long <jlong@messiah.edu>.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA  02110-1301, USA.
#
# This file incorporates work covered by the following copyright and
# permission notice. See the top-level AUTHORS file for more details.
#
#     This code is Copyright (C) 2001 Morgan Stanley Dean Witter, and
#     is distributed according to the terms of the GNU Public License
#     as found at <URL:http://www.fsf.org/copyleft/gpl.html>.
#
#     Written by Bennett Todd <bet@rahul.net>.
#
#
#
#

use strict;
use warnings;

package MySmtpServer;
use base "MSDW::SMTP::Server";

sub new
{
    my $class = shift;
    my %args = @_;
    my $self = bless \%args, $class;
	$self->{"in"} = new IO::Handle;
	$self->{"in"}->fdopen(fileno(STDIN), "r");
	$self->{"out"} = new IO::Handle;
	$self->{"out"}->fdopen(fileno(STDOUT), "w");
	$self->{"out"}->autoflush;
    $self->{"state"} = " accepted";
    return $self;
}

sub getline
{
	my ($self) = @_;
	local $/ = "\015\012";
	$/ = "\n" if ($self->{Translate});

	my $tmp = $self->{"in"}->getline;
	if (not defined $tmp)
	{
		return $tmp;
	}
	if ($self->{debug})
	{
		$self->{debug}->print($tmp);
	}
	$tmp =~ s/\n$/\015\012/ if ($self->{Translate});
	return $tmp;
}

sub print
{
	my ($self, @msg) = @_;
	my @transformed = $self->{Translate} ?
		( map { s/\015\012$/\n/; $_ } @msg ) : (@msg);
	$self->{debug}->print(@transformed) if defined $self->{debug};
	return $self->{"out"}->print(@transformed);
}

1;
