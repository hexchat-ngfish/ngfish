# ngFish - Hexchat OTR encryption plugin using Twofish in CBC mode
# 
# Advantages over FiSHLiM bundled into HexChat:
# * Twofish-CBC instead of Blowfish-ECB
# * 256-bit key using SHA2
# * Solid against common cryptanalysis
# * We do not reimplement cryptography
# * No bug relatively large utf-8 messages using non-latin characters. 
#   Any size data will be transmitted consistently without garbling.
#
# Fast dependencies (Crypt::Twofish, Crypt::CBC):
# * Debian/Ubuntu:  apt install libcrypt-twofish-perl libcrypt-cbc-perl 
# * RHEL/CentOS:    yum install perl-Crypt-Twofish perl-Crypt-CBC 
# * CPAN (no root): cpan -i Crypt::Twofish Crypt::CBC
#
# DH key exchange might be available in the next version
#

use strict;
use warnings;
use utf8;
use HexChat qw(:all);
use MIME::Base64;
use Digest::SHA qw(sha256);

use constant {
	
# config encryption password encoded in hex, you must change it before the first use
	CP => '0344ed6c3830fbe3f292ca8f82df',
	
# prepend a symbol before nicks in encrypted messages, you can change this
	ESIGN => "\x{2387}",
# RFC max message size in bytes
	RFCMAXLEN => 512,
# length of maximum output step increase per block in base64
	BINCR => 25,
# output length of first block in base64 (depends on random_bytes length used for header)
	BMINLEN => 45,
# input block size in bytes, shall be 16 (128 bits) for Twofish
	BSIZE => 16,
# prefix to store values in config file
	CPREFIX => 'ngf',
	
	PLUGIN_NAME => 'ngFish',
	PLUGIN_VERS => '1.1',
	PLUGIN_DESC => 'ngFish - Hexchat OTR encryption plugin using Twofish in CBC mode'

};

# enter FiSHLiM compatibility mode automatically if FiSHLiM is detected, 0 to disable
my $AUTOCOMPAT = 1; 
# prefix to identify encrypted messages
my $PREFIXDEFAULT = '+OK ';
# prefix to identify encrypted messages in compatibility mode with FiSHLiM
my $PREFIXCOMPAT = "+\x{041E}K ";

do { 
	die "ngFish won't work without $_ installed, please install this module first.\n" unless eval "require $_;1;" 
} foreach qw/Crypt::Twofish Crypt::CBC/;

register(PLUGIN_NAME, PLUGIN_VERS, PLUGIN_DESC, sub {
	prntf("%s plugin unloaded", PLUGIN_NAME);
});

my $PREFIX = $PREFIXDEFAULT;
my $COMPAT = 0;
if ( -f get_info("libdirfs") . '/fishlim.so' && $AUTOCOMPAT ) {
	$COMPAT = 1;
	# prefix to identify encrypted messages in FiSHLiM compatibility mode
	$PREFIX = $PREFIXCOMPAT;
	prntf("FiSHLiM exists, loading %s in compatibility mode. All commands are available with /ng* prefix.", PLUGIN_NAME);
}

my $actionchar = chr 1;
my $u = {}; # used for user@host masks because due to HC Perl interface poorness,
			# user_info() is not available in private messages
my $c = {}; 
my $prefs = plugin_pref_list();
foreach( keys %{ $prefs } ) {
	if ( /^\Q${\(CPREFIX)}\Ek(.+)/ ) {
		my $context = pack('H*',$1);
		my $str = config_value('decrypt', $prefs->{$_});
		my ($iv, $key) = (substr($str, 0, BSIZE), substr($str, BSIZE));
		$c->{$context} = new_crypt_object ($key, $iv);
	}
}

my $handle_outgoing = sub {

	# this is a workaround for empty user_info() in private messages
	# to get our user@host asap (better than nothing), this is important
	# for encrypted message length calculations
	if ( not exists $u->{context_info()->{server} . context_info()->{nick}} 
		 or (user_info() && $u->{context_info()->{server} . context_info()->{nick}} ne user_info()->{host}) )
	{
		$u->{context_info()->{server} . context_info()->{nick}} = user_info()->{host} if user_info();
	}

	return EAT_NONE unless exists $c->{lc context_info()->{channel}};

	my $message = $_[1][0];
	my $format = "PRIVMSG %s :%s%s";
	my $contarget = context_info()->{channel};

	my $nick = context_info()->{nick};
	utf8::decode($nick) if utf8::valid($nick);

	if ( $_[0][0] && uc $_[0][0] eq 'ME' ) {
		$message = $_[1][1];
		$format = "PRIVMSG %s :" . $actionchar . "ACTION %s%s" . $actionchar;
		emit_print( "Your Action", ESIGN . $nick , $message  );
	} else {
		emit_print( "Your Message", ESIGN . $nick , $message  );
	}

	my @encrypted = crypt_outgoing($contarget, $message);
	
	foreach ( @encrypted ) {
			commandf($format, $contarget, $PREFIX, $_);
	}
	
	return EAT_HEXCHAT;
};

my $handle_incoming = sub {

	return EAT_NONE unless exists $c->{lc context_info()->{channel}};
	
	my $type = uc $_[0][1];
	my $message = $type eq '332' ? $_[1][4] : $_[1][3];

	return EAT_NONE unless $message;
	
	$message =~ s/^://;
	my $channel = $type eq '332' ?  $_[0][3] :  $_[0][2];

	my $is_action;
	if ( $message =~ /^\Q$actionchar\EACTION\s(.+)/ ) {
		$message = $1;
		$message =~ s/\Q$actionchar\E$//;
		$is_action = 1;
	}
	
	my $iprefix = substr($message, 0, length($PREFIX));
	if ( $iprefix eq $PREFIXCOMPAT or $iprefix eq $PREFIXDEFAULT ) {
		
		my $xmessage = substr($message, length($PREFIX));
		$xmessage =~ s/\\/\n/g;
		my $dmessage = substr($c->{lc $channel}->decrypt(decode_base64($xmessage)), 16);
		utf8::decode($dmessage) if utf8::valid($dmessage);

		my $umask = $_[0][0];
		$umask =~ s/^://;


		my $command = 'RECV ';
	
		if ( $type eq '332' ) {
			my $nick = $_[0][2];
			my $host = $_[0][0];
			$host =~ s/^://;
			$command .= sprintf(":%s 332 %s %s :%s", $host, $nick, $channel, ESIGN . $dmessage);
		} else {
			my $is_private = lc $channel eq lc context_info()->{nick} ? 1 : 0;
			$dmessage = $actionchar . 'ACTION ' . $dmessage . $actionchar if $is_action;
			$command .= sprintf(":%s $type %s :%s", ($is_private ? '' : ESIGN) . $umask, $channel ,$dmessage);
		}

		command($command);
		
		return EAT_ALL;
	}

	return EAT_NONE;
};

my $helptext = {
	'setkey' => " [<nick or #channel>] <password>, sets the key for a channel or nick",
	'delkey' => " <nick or #channel>, deletes the key for a channel or nick",
	'notice+' => " <nick or #channel> <notice>, sends an encrypted notice to a channel or nick",
	'msg+' => " <nick or #channel> <message>, sends an encrypted message to a channel or nick",
	'topic+' => " <topic>, sets a new encrypted topic for the current channel",
};

my $cmds = {
	'setkey' => {
		compatname => "NGSETKEY",
		sub => sub {
			my $context = lc context_info()->{channel};
			my $key;

			if ( $_[0][1] && $_[0][2] ) {
				$context = lc $_[0][1];
				$key = $_[0][2];
			} elsif ( $_[0][1] ) {
				$key = $_[0][1];
			} else  {
				prntf('Usage: ' . $_[0][0] . $helptext->{setkey});
				return EAT_HEXCHAT;
			}

			$key = sha256($key) for (1..8);
			my $iv = Crypt::CBC->random_bytes(BSIZE);

			plugin_pref_set(CPREFIX . 'k' . unpack('H*',$context), config_value('encrypt', $iv . $key));
			delete $c->{$context} if exists $c->{$context};
			$c->{$context} = new_crypt_object ($key, $iv);
											  
			prntf("Stored key for %s", $context);

			return EAT_HEXCHAT;
		}
	},
	'delkey' => {
		compatname => "NGDELKEY",
		sub => sub {
			my $context = lc $_[0][1];
			unless ( $context ) {
				prntf('Usage: ' . $_[0][0] . $helptext->{delkey});
				return EAT_HEXCHAT;
			}

			unless ( exists $c->{$context} ) {
				prntf("No stored key found for %s", $context);
				return EAT_HEXCHAT;
			}

			plugin_pref_delete(CPREFIX . 'k' . unpack('H*',$context));
			delete $c->{$context};

			prntf("Deleted key for %s", $context);

			return EAT_HEXCHAT;
		}
	},
	'notice+' => {
		compatname => "NGNOTICE+",
		sub => sub {
			my $context;
			my $message;

			if ( $_[0][1] && $_[0][2] ) {
				$context = lc $_[0][1];
				$message = $_[1][2];
				unless (exists $c->{lc $context}) {
					prntf("%s error, no key found for %s.", $_[0][0], $context);
					return EAT_HEXCHAT;
				}
			} else  {
				prntf('Usage: ' . $_[0][0] . $helptext->{'notice+'});
				return EAT_HEXCHAT;
			}

			my @encrypted = crypt_outgoing($context, $message);
		
			foreach ( @encrypted ) {
					emit_print( "Notice Send", ESIGN . $context , $message  );
					commandf("quote NOTICE %s :%s%s", $context, $PREFIX, $_);
			}
			
			return EAT_HEXCHAT;
		}
	},
	'msg+' => {
		compatname => "NGMSG+",
		sub => sub {
			my $context;
			my $message;
			my $nick = user_info()->{nick};
			utf8::decode($nick) if utf8::valid($nick);

			if ( $_[0][1] && $_[0][2] ) {
				$context = lc $_[0][1];
				$message = $_[1][2];
				unless (exists $c->{lc $context}) {
					prntf("%s error, no key found for %s.", $_[0][0], $context);
					return EAT_HEXCHAT;
				}
			} else  {
				prntf('Usage: ' . $_[0][0] . $helptext->{'msg+'});
				return EAT_HEXCHAT;
			}

			my @encrypted = crypt_outgoing($context, $message);
		
			foreach ( @encrypted ) {
					emit_print( "Your Message", ESIGN . $nick , $message  );
					commandf("PRIVMSG %s :%s%s", $context, $PREFIX, $_);
			}
			
			return EAT_HEXCHAT;
		}
	},
	'topic+' => {
			compatname => "NGTOPIC+",
			sub => sub {
				my $context = lc context_info()->{channel};
				my $message;
	
				if ( $_[0][1] ) {
					$message = $_[1][1];
					unless (exists $c->{lc $context}) {
						prntf("%s error, no key found for %s.", $_[0][0], $context);
						return EAT_HEXCHAT;
					}
				} else  {
					prntf('Usage: ' . $_[0][0] . $helptext->{'topic+'});
					return EAT_HEXCHAT;
				}
	
				my @encrypted = crypt_outgoing($context, $message);

				commandf("TOPIC %s %s%s", $context, $PREFIX, $encrypted[0]);
				
				return EAT_HEXCHAT;
			}
		},
};

sub crypt_outgoing {
	my $contarget = shift;
	my $message = shift;
	
	# a workaround for empty user_info() in private messages
	my $umask = context_info->{nick} . '!';
	if (user_info()) {
		$umask .= user_info()->{host};
	} elsif (exists $u->{context_info()->{server} . context_info()->{nick}}) {
		$umask .=  $u->{context_info()->{server} . context_info()->{nick}};
	} else {
		# this is used when we can't get a self hostmask
		$umask .=  'dummyrandom@DEADBEEF.DEADBEEF.DEADBEEF.IP';
	}

	my @mlen;
	{
		no utf8;
		use bytes;
		push @mlen, length $message;
		push @mlen, length ':' . $umask . ' PRIVMSG ' . $contarget . ' :' . $PREFIX;
	}
	
	# calculation of an estimate maximum message size, not the best idea but working well
	my $precalc = int((int($mlen[0] / BSIZE) * BINCR + BMINLEN) / (RFCMAXLEN - $mlen[1])) + 1;
	my $chunklen = int(length($message) / $precalc);
	
	my @chunks = unpack("(a$chunklen)*", $message);

	my @encrypted;
	foreach ( @chunks ) {
		my $encrypted = encode_base64($c->{lc $contarget}->encrypt(unpack('H*',Crypt::CBC->random_bytes(BSIZE/2)) . $_));
		$encrypted =~ s/\n/\\/g;
		$encrypted =~ s/=//g;
		$encrypted =~ s/\\$//;
		push @encrypted, $encrypted;
	}
	
	return @encrypted;
}

sub new_crypt_object {
	my $key = shift;
	my $iv = shift;

	return Crypt::CBC->new(
		-key => $key, 
		-literal_key => 1, 
		-iv => $iv,
		-blocksize => BSIZE, 
		-header => 'none', 
		-keysize => length($key), 
		-cipher => 'Twofish'
	);
}

sub config_value {
	my $command = shift;
	my $value = shift;
	my $x = Crypt::CBC->new( -key => pack ('H*',CP), -cipher => 'Twofish' );

	if ($command eq 'encrypt') {
		my $v = encode_base64($x->encrypt($value));
		$v =~ s/\n/\\/g;
		return $v;
	} elsif ($command eq 'decrypt') {
		$value =~ s/\\/\n/g;
		return $x->decrypt(decode_base64($value));
	}
}


hook_command("", $handle_outgoing);
hook_command("ME", $handle_outgoing);
hook_command($COMPAT ? $cmds->{'setkey'}->{compatname} : "SETKEY", $cmds->{'setkey'}->{sub}, { help_text => ($COMPAT ? $cmds->{'setkey'}->{compatname} : "SETKEY") . $helptext->{'setkey'} });
hook_command($COMPAT ? $cmds->{'delkey'}->{compatname} : "DELKEY", $cmds->{'delkey'}->{sub}, { help_text => ($COMPAT ? $cmds->{'delkey'}->{compatname} : "DELKEY") . $helptext->{'delkey'} });
hook_command($COMPAT ? $cmds->{'notice+'}->{compatname} : "NOTICE+", $cmds->{'notice+'}->{sub}, { help_text => ($COMPAT ? $cmds->{'notice+'}->{compatname} : "NOTICE+") . $helptext->{'notice+'} });
hook_command($COMPAT ? $cmds->{'msg+'}->{compatname} : "MSG+", $cmds->{'msg+'}->{sub}, { help_text => ($COMPAT ? $cmds->{'msg+'}->{compatname} : "MSG+") . $helptext->{'msg+'} });
hook_command($COMPAT ? $cmds->{'topic+'}->{compatname} : "TOPIC+", $cmds->{'topic+'}->{sub}, { help_text => ($COMPAT ? $cmds->{'topic+'}->{compatname} : "TOPIC+") . $helptext->{'topic+'} });
hook_server("TOPIC", $handle_incoming);
hook_server("332", $handle_incoming);
hook_server("PRIVMSG", $handle_incoming);
hook_server("NOTICE", $handle_incoming);
prntf("%s plugin loaded", PLUGIN_NAME);

