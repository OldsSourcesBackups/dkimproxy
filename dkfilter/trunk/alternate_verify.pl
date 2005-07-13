# Somehow the below verification code excerpt will show how to do
# a verification without loading the entire message into memory at
# once. It assumes the SHA1 hash has already been calculated, and
# is $calculated_hash.
#
# The function takes $sig as the DomainKeys signature header.
# $pubk is the public key as fetched from DNS.
# The DK function computes $expected_hash from the signature.
# If $expected_hash eq $calculated_hash, it is a valid signature.

# From Joshua Tauberer's Thunderbird Extension for Sender Verification
# http://taubz.for.net/code/spf/

use Crypt::RSA::Primitives;
use Crypt::RSA::DataFormat qw(octet_len os2ip i2osp octet_xor mgf1);
use Crypt::RSA::Key::Public;

sub DK {
    my $sig = shift;
	$sig = Mail::DomainKeys::Signature->parse(String => $sig);

	# Fetch the public key
	my $pubk = fetch Mail::DomainKeys::Key::Public(
		Protocol => $sig->protocol,
		Selector => $sig->selector,
		Domain => $sig->domain);
	if (!defined($pubk)) { return undef; }
	if ($pubk->revoked) { return undef; }

	# TODO - check granularity

    # The following is based on Crypt::RSA::SS::PSS.
    # If anyone reading can get this to work with
    # $pubk->cork directly, that'd be preferable.

    my ($kn, $ke) = $pubk->cork->get_key_parameters();
    my $key = bless { e => $ke->to_decimal, n => $kn->to_decimal }, 'Crypt::RSA::Key::Public';

    my $rsa = Crypt::RSA::Primitives->new();
    my $S = MIME::Base64::decode($sig->signature);
    my $k = octet_len ($key->n);
    my $s = os2ip ($S);
    my $m = $rsa->core_verify (Key => $key, Signature => $s) || return undef;
    my $em1 = i2osp ($m, $k-1) || return undef;
    $em1 = substr($em1, length($em1) - 20, 20);
    $em1 = MIME::Base64::encode($em1);
    $em1 =~ s/[=\s]+$//;
    return ($sig->domain, $em1);
}

# usage
# ($dkdomain, $expected_hash) = DK($header)
# if ($expected_hash eq $calculated_hash)
# {
#     $result = "pass";
#     $comment = "Verified from <$dkdomain>"
# }


