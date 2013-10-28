
BASEDIR= ..
include $(BASEDIR)/platform
#include $(BASEDIR)/Makefile.$(OS)

SUBDIRS = linux netbsd freebsd 

all:
	@$(MAKE) -C .. all

install:
	@$(MAKE) -C .. install

all-driver: 
	@for i in $(PLATFORM) ;\
	do \
	if [ -d "$$i" ]; then \
		(cd $$i && \
		$(MAKE) all-$$i) \
		|| exit 1; \
	fi; \
	done;

clean:
	@$(MAKE) -C .. clean

clean-driver:
	@for i in $(PLATFORM) ;\
	do \
	if [ -d "$$i" ]; then \
		(cd $$i && \
		$(MAKE) clean-$$i) \
		|| exit 1; \
	fi; \
	done;


#
# $Id: Makefile,v 1.1 2007/01/13 03:03:57 panicker Exp $
# $Log: Makefile,v $
# Revision 1.1  2007/01/13 03:03:57  panicker
# Makefiles
#
# Revision 1.5  2006/01/18 16:00:02  pyelgar
#   - Merged IPSec changes with cvs head.Changed the macro cavium_softirq_en/disab    le to accept a integer variable as input.
#
# Revision 1.4  2005/08/31 18:08:39  bimran
# Removed multiple includes.
#
# Revision 1.3  2004/07/07 18:02:23  tsingh
# compilation issues
#
# Revision 1.2  2004/06/28 21:24:09  tahuja
# NetBSD port & OSI Makefile.
#
# Revision 1.1  2004/04/15 22:40:47  bimran
# Checkin of the code from India with some cleanups.
#
#
