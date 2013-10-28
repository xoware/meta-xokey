BASEDIR= ..
include $(BASEDIR)/platform

SUBDIRS= pots speed-ssl speed-ipsec

all: all-utils

all-utils: os_depend_make sub_install

os_depend_make:
	@if test $(OS) = Linux ; then \
		$(MAKE) -f utils-$(OS).mk all-utils-$(OS); \
	fi;
	@if test $(OS) = FreeBSD ; then \
		$(MAKE) -f utils-$(OS).mk all-utils-$(OS); \
	fi;
	
sub_install:
	@for i in $(SUBDIRS) ;\
	do \
	if [ -d "$$i" ]; then \
		(cd $$i && \
		$(MAKE) all-$$i) \
	fi; \
	done;
		

clean: clean-utils

clean-utils: os_depend_clean sub_clean 

os_depend_clean:
	@if test $(OS) = Linux ; then \
		$(MAKE) -f utils-$(OS).mk clean-utils-$(OS); \
	fi;
	@if test $(OS) = FreeBSD ; then \
		$(MAKE) -f utils-$(OS).mk clean-utils-$(OS); \
	fi;

sub_clean:
	@for i in $(SUBDIRS) ;\
	do \
	if [ -d "$$i" ]; then \
		(cd $$i && \
		$(MAKE) clean-$$i) \
	fi; \
	done;
