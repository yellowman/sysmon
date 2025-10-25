#
# This makefile is mostly for the developers of the program
# run from top level directory using make -f autoconf/Makefile
# targets:
# autoconf  (builds configure)
# distclean (cleans up for distribution)
# clean     (clean up objects and binaries in src/)
#

SHELL= /bin/sh
AUTOCONF= autoconf
AUTOHEADER= autoheader
CHMOD= chmod
RM= rm -f

#


all:
	@echo "Read the README file"

always:	/dev/null

conf:
	@$(SHELL) ./configure

autoconf:	always
	$(AUTOCONF) autoconf/configure.in >configure
	$(AUTOHEADER) autoconf/configure.in >autoconf/defines.h.in
	-$(CHMOD) 755 configure

clean:
	-$(RM) src/*.o src/sysmon src/sysmond src/block

distclean:	clean
	-$(RM) configure src/Makefile src/defines.h autoconf/defines.h.in
	-$(RM) config.*
