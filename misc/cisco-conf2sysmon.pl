#!/usr/bin/perl
#
# (c) 2000 - Daniel J. Luke <dluke@geeklair.net> 
# May be distributed under the Gnu Public License
# Available at http://www.gnu.org/copyleft/gpl.html
#

if( $ARGV[0] eq '' or $ARGV[1] eq '')
{
	print "Usage: makeconf.pl host /path/to/inputfile\n";
	exit;
}

$host = $ARGV[0];

open( IN, "<$ARGV[1]" ) or die "Unable to open file: $ARGV[1]\n";
open( OUT, ">$host.conf" ) or die "Unable to create file: $host.conf\n";

print OUT "object $host {\n";
print OUT "	ip \"$host\";\n";
print OUT "	type ping;\n";
print OUT "	desc \"$host\";";
print OUT "};\n\n";

foreach( <IN> )
{
	chomp $_; #get rid of trailing newline
	$_ =~ s/^\s+//g; #get rid of spaces at the start of the line

	if( $_ =~ /^\!/ ) #-- comment line
	{
		#do nothing
		#print "Found a comment line\n";
	}

	if( $_ =~ /^interface / ) #--new host
	{
		if( $hostinfo[0] ne '' and
		    $hostinfo[1] ne '' ) #--if we have all the data

		{
			#print out a record
			print OUT "object $host-$hostinfo[0] {\n";
			print OUT "	ip \"$hostinfo[1]\";\n";
			print OUT "	type ping;\n";
			print OUT "	desc \"$host-$hostinfo[0] $hostinfo[2]\";\n";
			print OUT "	dep \"$host\";\n";
			print OUT "};\n\n";
			
			$hostinfo[0] = '';
			$hostinfo[1] = '';
			$hostinfo[2] = '';
		}

		$hostinfo[0] = substr($_, 10); #--pull off 'interface '
	}
	elsif( $_ =~ /^ip address / )
	{
		$temp = substr($_, 11); #--pull off 'ip address '
		
		#-- hack off the subnet mask
		($hostinfo[1], $temp) = split( / /, $temp );

	}
	elsif( $_ =~ /^description / )
	{
		if ( $hostinfo[0] ne '')
		{
			$hostinfo[2] = substr($_, 12); #--pull off 'description '
		}
	}
	
	# else we have data we don't care about
}

#get the last host if applicable

if( $hostinfo[0] ne '' and
    $hostinfo[1] ne '' ) #--if we have all the data
{
	#print out a record
        print OUT "object $host-$hostinfo[0] {\n";
        print OUT "     ip \"$hostinfo[1]\";\n";
        print OUT "     type ping;\n";
        print OUT "     desc \"$host-$hostinfo[0] $hostinfo[2]\";\n";
        print OUT "     dep \"$host\";\n";
        print OUT "};\n";
}


close( IN );
close( OUT );

exit;

