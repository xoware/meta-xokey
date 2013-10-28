BASEDIR= ../..
include $(BASEDIR)/platform

all: all-pots

all-pots: 
	@if test $(OS) = Linux ; then \
		$(MAKE) -f pots-$(OS).mk all-pots-$(OS); \
	fi;
	@if test $(OS) = FreeBSD ; then \
		$(MAKE) -f pots-$(OS).mk all-pots-$(OS); \
	fi;

clean: clean-pots

clean-pots:
	@if test $(OS) = Linux ; then \
		$(MAKE) -f pots-$(OS).mk clean-pots-$(OS); \
	fi;
	@if test $(OS) = FreeBSD ; then \
		$(MAKE) -f pots-$(OS).mk clean-pots-$(OS); \
	fi;
