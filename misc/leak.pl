#!/usr/bin/perl

while (<STDIN>)
{
	@line = split(/ /, $_);
	if ($line[0] eq "DMEM-Allocated")
	{
		$mem{$line[3]} = $line[6];
	}
	if ($line[0] eq "DMEM-Freeing")
	{
		$mem{$line[2]} = "poo";
	}
}

foreach $val (keys %mem){
	if ($val ne "poo") {
	print "did not free $val\n";
	}
		
}

