#!/usr/local/bin/perl -w
# sysmon_convert: attempt to make a decent sysmon v 0.91 config file from
# an old config file.
#
# Last modified: Sat Dec 22 02:48:12 PST 2001 SWI
#

$LASTNF = 0;
$ROOT = 0;
$ROOTDEP = "";
%LABELS = ();

print "config noheartbeat;\n";

while (<>) {
	if (/^[;#](.*)/) { print "#$1\n"; next; } 
	if (/^\s*config\s+/i) { print &mangle_config_line($_); next; }
	if (/^\s+$/) { print; next; } 
	chomp;
	$device = &parse_line($_);
	&emit($device);
}

#                /* ex: hostname tcp # desc "spawn" email { } */
#                /* ex: hostname udp # desc "spawn" email { }*/
#                /* ex: hostname ping desc "spawn" email { }*/
#                /* ex: hostname nntp desc "spawn" email { }*/
#                /* ex: hostname smtp desc "spawn" email { }*/
#                /* ex: hostname sysmon desc "spawn" email { }*/
#                /* ex: hostname ssh desc "spawn" email { }*/
#                /* ex: hostname umichx500 desc "spawn" email { }*/
#                /* ex: hostname imap user pw desc "spawn" email { }*/
#                /* ex: hostname pop3 user pw desc "spawn" email { }*/
#                /* ex: hostname pop2 user pw desc "spawn" email { }*/
#                /* ex: hostname http /file text desc "spawn" email { }*/
#		 /* ex: hostname radius user pw radsecret email { }*/

sub mangle_config_line {
	my $line = $_[0];
	my ($type, $path);

	$line =~ s/^\s+//;
	if ($line =~ m/^config\s+statusfile/i) {
		$line =~ m#^config\s+statusfile\s+(text|html)\s+(.*)#i;
		return "config statusfile $1 \"$2\";\n";
	} elsif ($line =~ m/^config\s+logging/i) {
		$line =~ m#^config\s+logging\s+(.*)#i;
		return "config logging syslog \"$1\";\n";
	} elsif ($line =~ m/^config\s+numfailures/i) {
		$line =~ m#^config\s+numfailures\s+(.*)#i;
		if ($LASTNF != 0+$1) {
			$LASTNF= $1;
			return "config numfailures $1;\n";
		} else {
			return "\n"; # suppressing multiple config-NF
		}
	}
	$line =~ s/$/;/;
	return $line;
}

sub parse_line {
	my $line = $_[0];
	my %params = ();

	$line =~ s/^\s+//g;
	$line =~ s/\s+$//g;
	if ($line =~ /}$/) {
		pop (@depstack); return \%params;
	} else {
	
	my @tokens = split(/[ \t]+/, $line);
	if (@tokens) {
		$params{'host'}	= shift(@tokens) || 'UNKNOWN';
		$params{'type'}	= shift(@tokens) || 'UNKNOWN';
		if ($params{'type'} eq 'tcp') {
			$params{'port'}	= shift(@tokens);
			$params{'desc'}	= shift(@tokens);
			$params{'email'} = shift(@tokens);
			if ($params{'port'} eq "80") {
				$params{'type'} = "http";
				$params{'url'} = "/";
				$params{'urltext'} = "<BODY>";
			}
		} elsif ($params{'type'} eq 'udp') {
			$params{'port'}	= shift(@tokens);
			$params{'desc'}	= shift(@tokens);
			$params{'email'} = shift(@tokens);
		} elsif ($params{'type'} eq 'ping') {
			$params{'desc'}	= shift(@tokens);
			$params{'email'} = shift(@tokens);
		} elsif ($params{'type'} eq 'nntp') {
			$params{'desc'}	= shift(@tokens);
			$params{'email'} = shift(@tokens);
		} elsif ($params{'type'} eq 'smtp') {
			$params{'desc'}	= shift(@tokens);
			$params{'email'} = shift(@tokens);
		} elsif ($params{'type'} eq 'imap') {
			$params{'user'}	= shift(@tokens);
			$params{'pw'}	= shift(@tokens);
			$params{'email'} = shift(@tokens);
		} elsif ($params{'type'} eq 'pop3') {
			$params{'user'}	= shift(@tokens);
			$params{'pw'}	= shift(@tokens);
			$params{'email'} = shift(@tokens);
		} elsif ($params{'type'} eq 'radius') {
			$params{'user'}	= shift(@tokens);
			$params{'pw'}	= shift(@tokens);
			$params{'radsecret'} = shift(@tokens);
			$params{'email'} = shift(@tokens);
		} else {
			print "# UNKNOWN: $line\n";
			%params = ();
		}
	}
	}
	#
	# An attempt to make the object labels friendly.
	#

	if (defined ($params{'host'}) and defined($params{'type'})) {
		my $label = "";
		if (($params{'type'} eq "tcp") or 
			($params{'type'} eq "udp")) {
			$label = $params{'desc'}."-".$params{'host'};
			if (defined($LABELS{$label})) {
				$label = $params{'type'}."-".$params{'port'}.
					"-".$params{'host'};
			}
		} elsif ($params{'type'} eq "ping") {
			$label = $params{'host'};
			if (defined($LABELS{$label})) {
				$label = $params{'type'}."-".$params{'host'};
			}
		} else {
			$label = $params{'type'}."-".$params{'host'};
		}
		$params{'label'} = $label;
		$LABELS{$label} = 1;
	}
	if (@depstack) {
		$params{'depends'} = $depstack[0];
	}
	if ($line =~ m#\s+[{]$#) { push (@depstack, $params{'label'}); }
	return \%params;
}

sub emit {
	my $href = $_[0];
	if ($href && defined($href->{'label'})) {
	if (!$ROOT) { print "\nroot=\"".$href->{'label'}."\";\n\n"; $ROOT=1;
		$ROOTDEP = $href->{'label'};
	}
	print "object ",$href->{'label'}," {\n";
	print "\t",'ip "',$href->{'host'},'";',"\n";
	print "\t",'type ',$href->{'type'},';',"\n";

	if ($href->{'type'} eq 'udp') {
		print "\t",'port ',$href->{'port'},';',"\n";
	} elsif ($href->{'type'} eq 'tcp') {
		print "\t",'port ',$href->{'port'},';',"\n";
	} elsif ($href->{'type'} eq 'imap') {
		print "\t",'username "',$href->{'user'},'";',"\n";
		print "\t",'password "',$href->{'pw'},'";',"\n";
	} elsif ($href->{'type'} eq 'pop3') {
		print "\t",'username "',$href->{'user'},'";',"\n";
		print "\t",'password "',$href->{'pw'},'";',"\n";
	} elsif ($href->{'type'} eq 'radius') {
		print "\t",'username "',$href->{'user'},'";',"\n";
		print "\t",'password "',$href->{'pw'},'";',"\n";
		print "\t",'secret "',$href->{'radsecret'},'";',"\n";
	} elsif ($href->{'type'} eq 'http') {
		print "\t",'url "',$href->{'url'},'";',"\n";
		print "\t",'urltext "',$href->{'urltext'},'";',"\n";
	} elsif ($href->{'type'} eq 'nntp') {
		print "\tport 119;\n";
	} else {
		# defaults.
	}

	if (defined($href->{'depends'})) {
		print "\t",'dep "',$href->{'depends'},'";',"\n";
	} else {
		print "\t",'dep "',$ROOTDEP,'";',"\n";
	}
	if (defined($href->{'desc'})) {
		print "\t",'desc "',$href->{'desc'},'";',"\n";
	}
	if (defined($href->{'email'})) {
		print "\t",'contact "',$href->{'email'},'";',"\n";
	}
	print "};\n";
	}
}

# EOF
