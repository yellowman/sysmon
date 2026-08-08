## makefile for sysmon
##
## jared@puck.nether.net
##

all: src/Makefile
	(cd src; make )
	@if command -v go >/dev/null 2>&1; then \
		(cd web-ui && make); \
	else \
		echo "*** No go toolchain found - the daemon is built, the web UI is not."; \
		echo "*** Build it later with: cd web-ui && make"; \
	fi

## The web UI on its own, for a box that has go but does not need the
## daemon rebuilt.
web:
	(cd web-ui && make)

sysmon-ping-helper: src/Makefile
	(cd src; make sysmon-ping-helper)

clean:
	-(cd src ; make clean)
	-(cd web-ui ; make clean)
	rm -f src/Makefile
	rm -f src/defines.h
	rm -f config.status config.log config.cache confdefs.h

install: src/Makefile
	(cd src; make install)
	@if command -v go >/dev/null 2>&1; then \
		(cd web-ui && make install); \
	else \
		echo "*** No go toolchain found - the web UI was not installed."; \
	fi

install-web:
	(cd web-ui && make install)

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
