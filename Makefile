## makefile for sysmon
##
## jared@puck.nether.net
##

all: src/Makefile
	(cd src; make )

clean: 
	-(cd src ; make clean)
	rm -f src/Makefile
	rm -f src/defines.h
	rm -f config.status config.log config.cache confdefs.h

install: src/Makefile
	(cd src; make install)

register: src/Makefile
	(cd src; make register)


## For use by me (jared) only
beta:
	-make clean
	echo "*** DID YOU UPDATE THE VERS define in src/config.h ***"
	sleep 3
	( cd ..; tar --exclude CVS -zcvf ~/anonftpdir/beta/sysmon-devel.`date +%Y%m%d.%H%M`.tar.gz sysmon/ )

src/Makefile: configure
	./configure
