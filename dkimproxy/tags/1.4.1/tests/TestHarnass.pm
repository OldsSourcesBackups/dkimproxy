package TestHarnass;

use strict;
use warnings;

my $path = "../scripts";

sub new
{
	my $class = shift;
	my $self = bless {}, $class;
	return $self;
}

sub make_private_key
{
	my $self = shift;
	my ($filename) = @_;

	return if (-f $filename);
	system("openssl", "genrsa", "-out", $filename, "1024");
	die if $? != 0;
}

sub start_servers
{
	my $self = shift;

	$self->{proxy_args} ||= [];
	$self->{proxy_port} ||= 20025;
	$self->{sink_port} ||= 20026;

	# launch the SMTP sink
	my $sink_fh;
	$self->{sink_pid} = open($sink_fh, "-|",
			"./smtp_sink.pl", "--port=20026")
		or die "Error: cannot spawn smtp_sink.pl process: $!\n";
	$self->{sink_fh} = $sink_fh;

	# wait for it to be ready
	my $tmp = <$sink_fh>;
	if (not $tmp)
	{
		die "Error: smtp_sink.pl failed to start\n";
	}

	# launch DKIMproxy
	my $pidfile = "/tmp/pidfile$$";
	$self->{proxy_pid} = fork;
	if ($self->{proxy_pid} == 0)
	{
		exec("$path/dkimproxy.out",
		@{$self->{proxy_args}},
		"--pidfile=$pidfile",
		"127.0.0.1:$self->{proxy_port}",
		"127.0.0.1:$self->{sink_port}",
		)
		or do {
			$self->shutdown_servers;
			die "Error: cannot spawn dkimproxy.out process: $!\n";
			};
	}
	elsif (not defined $self->{proxy_pid})
	{
		$self->shutdown_servers;
		die "fork: $!\n";
	}

	# wait for DKIMproxy
	my $elapsed = 0;
	until (-f $pidfile)
	{
		sleep 1;
		$elapsed++;
		if ($elapsed >= 6) {
			$self->shutdown_servers;
			die "Error: dkimproxy.out (pid $self->{proxy_pid}) failed to create PID file\n";
		}
	}

	print "# have pids $self->{sink_pid}, $self->{proxy_pid}\n";
	return;
}

sub shutdown_servers
{
	my $self = shift;

	if ($self->{proxy_pid})
	{
		print STDERR "shutting down proxy...\n";
		kill "TERM", $self->{proxy_pid};
		wait;
		delete $self->{proxy_pid};
	}

	if ($self->{sink_pid})
	{
		print STDERR "shutting down sink...\n";
		kill "TERM", $self->{sink_pid};
		wait;
		my $sink_fh = $self->{sink_fh};
		close $sink_fh;
		delete $self->{sink_fh};
		delete $self->{sink_pid};
	}

	return;
}

sub process_message_file
{
	my $self = shift;
	my ($msgfile) = @_;

	use Net::SMTP;
	my $smtp = Net::SMTP->new("localhost:$self->{proxy_port}")
		or die "Error: cannot connect to DKIMproxy: $!\n";
	$smtp->mail("nobody");
	$smtp->to("nobody");
	$smtp->data;

	open MSG, "<", $msgfile
		or die "$msgfile: $!\n";
	while (<MSG>)
	{
		$smtp->datasend($_);
	}
	close MSG
		or die "$msgfile: $!\n";
	$smtp->dataend;
	$smtp->quit;

	# read the message from the SINK
	my $sink_fh = $self->{sink_fh};
	my $msg_encoded = <$sink_fh>;
	use URI::Escape;
	return uri_unescape($msg_encoded);
}

sub generate_signatures
{
	my $self = shift;
	my ($msgfile) = @_;

	my $new_msg = $self->process_message_file($msgfile);
	use Mail::DKIM::Verifier;
	my $dkim = Mail::DKIM::Verifier->new();
	$dkim->PRINT($new_msg);
	$dkim->CLOSE;

	return $dkim->signatures;
}

1;
