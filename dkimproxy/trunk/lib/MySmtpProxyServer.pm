#!/usr/bin/perl -I../lib
#
# Copyright (c) 2005 Messiah College. This program is free software.
# You can redistribute it and/or modify it under the terms of the
# GNU Public License as found at http://www.fsf.org/copyleft/gpl.html.
#
# Written by Jason Long, jlong@messiah.edu.

#
#   This code is Copyright (C) 2001 Morgan Stanley Dean Witter, and
#   is distributed according to the terms of the GNU Public License
#   as found at <URL:http://www.fsf.org/copyleft/gpl.html>.
#
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
# Written by Bennett Todd <bet@rahul.net>

use warnings;
use strict;

use MSDW::SMTP::Server;
use MSDW::SMTP::Client;
use Net::Server;
use MySmtpServer;
use IO::File;

package MySmtpProxyServer;
use base "Net::Server::MultiType";

#get the next message from the connecting system
sub _chat
{
	my $self = shift;
	if ($self->{smtp_server}->{state} !~ /^data/i)
	{
		return $self->{smtp_server}->chat(@_);
	}
	else
	{
		return $self->_chat_data;
	}
}

sub _chat_data
{
	my $self = shift;
	my $server = $self->{smtp_server};
	local(*_);

	if (defined($server->{data}))
	{
		$server->{data}->seek(0, 0);
		$server->{data}->truncate(0);
	}
	else
	{
		$server->{data} = IO::File->new_tmpfile;
	}
	while (defined($_ = $server->getline))
	{
		if ($_ eq ".\r\n")
		{
			$server->{data}->seek(0,0);
			return $server->{state} = '.';
		}
		s/^\.\./\./;
		$self->handle_message_chunk($_);
	}
	# the system that connected to us dropped the connection
	# before finishing the message
	return(0);
}

=head2 process_request() - handles a new connection from beginning to end

=cut

sub process_request
{
	my $self = shift;

	my $server = $self->{smtp_server} = $self->setup_server_socket;
	my $client = $self->{smtp_client} = $self->setup_client_socket;

	# wait for SMTP greeting from destination
	my $banner = $client->hear;

	# emit greeting back to source
	$server->ok($banner);

	# begin main SMTP loop
	#  - wait for a command from source
	while (my $what = $self->_chat)
	{
		if ($self->{debug})
		{
			print STDERR $what . "\n";
		}
		$self->handle_command($what)
			or last;
	}
}

=head2 handle_command() - handles a single SMTP command

  $server->handle_command($what);

$what is an SMTP command, like "mail from:<somebody@example.com>",
or the special "end-of-data" command, ".".

The result should be true to keep the connection open,
or false to close it.

=cut

sub handle_command
{
	my $self = shift;
	my ($what) = @_;
	my $server = $self->{smtp_server};
	my $client = $self->{smtp_client};

	if ($what eq '.')
	{
		if ($self->handle_end_of_data)
		{
			$server->ok($client->hear);
			return 1;
		}
		else
		{
			return;
		}
	}
	else
	{
	    $client->say($what);
		$server->ok($client->hear);
		return if $what =~ /^quit/i;
		return 1;
    }
}

#called when a part of the message being received has been received
#this method saves the chunk to a temporary file so that the
#entire message can be played back after processing
#
sub handle_message_chunk
{
	my $self = shift;
	my ($data) = @_;

	$self->{smtp_server}->{data}->print($data)
		or die "Error saving message to temporary file: $!\n";
}

=head2 handle_end_of_data() - source has finished transmitting the message

  my $result = $server->handle_end_of_data($client);

This method is called when the source finishes transmitting the message.
This method may filter the message and if desired, transmit the message
to $client. Alternatively, this method can respond to the server with
some sort of rejection (temporary or permanent).

The result is nonzero if a message was transmitted to the next server
and its response returned to the source server, or zero if the message
was rejected and the connection to the next server should be dropped.

=cut

sub handle_end_of_data
{
	my $self = shift;
	my $server = $self->{smtp_server};
	my $client = $self->{smtp_client};
	my $fh = $server->{data};

	# send the message unaltered
	$fh->seek(0,0);
	$client->yammer($fh);

	return 1;
}

=head2 setup_client_socket() - create socket for sending the message

=cut

# setup_server_socket() - create socket for receiving the message
#
# No use in overriding this, I think.
#
sub setup_server_socket
{
	my $self = shift;

	# create an object for handling the incoming SMTP commands
	return new MySmtpServer;
}

1;
