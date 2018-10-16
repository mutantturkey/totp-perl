use MIME::Base32;
use POSIX ;
use Digest::SHA;
use v5.14;

# take a string, make it a hex and run HMAC on it
sub  hmac_sha1_hex_string {
	my ($data, $key) = map pack('H*', $_), @_;
	return Digest::SHA::hmac_sha1_hex($data, $key);
}

# make a usable number out of that HMAC result
sub hotp_truncate {
	my ($hex) = @_;
	my $lastbyte= substr $hex, -2;
	my $offset = (hex $lastbyte) & 0xf;
	my $offset = $offset * 2;

	my $truncate = (
		(hex substr($hex, $offset    , 2) & 0x7f) << 24 | 
		(hex substr($hex, $offset + 2, 2) & 0xff) << 16 | 
		(hex substr($hex, $offset + 4, 2) & 0xff) << 8 | 
		(hex substr($hex, $offset + 6, 2) & 0xff) 
	);

	# 6 letter;
	$truncate = substr($truncate, -6);

	return $truncate;
}

# TOTP is HOTP(K,c) where counter c is time based and changed every x seconds (30 here)
sub totp {
	my ($time, $secret) = @_;

	# definition for otp(K,c) where c is the counter -> with totp, we use time / 30
	$time = floor($time / 30);

	# do the work
	my $otp = hotp($time, $secret);

	return $otp;
}

# basically HMAC(key, counter)
sub hotp {
	my ($time, $secret) = @_;

	my $secret_hex = unpack "H*", decode_base32($secret);
	my $time_hex= sprintf("%016s", sprintf("%x", $time));

	# SHA-1 Hex your secret 
	my $hash = hmac_sha1_hex_string($time_hex, $secret_hex);

	# run trunc to generate a user useable number
	my $otp = hotp_truncate($hash);

	return $otp;
}

my $secret = "";
if($#ARGV != 0)  {
	$secret = <STDIN>;
	chomp $secret;
} else {
	$secret = $ARGV[0] ;
}

my $starttime = time;

my $otp = totp($starttime, $secret);

printf("%ds left: %06d, in your clipboard\n", 30 - $starttime % 30, $otp);
system("echo $otp | xclip /dev/stdin");
