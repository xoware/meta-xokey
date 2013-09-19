DESCRIPTION = "GNU libmicrohttpd is a small C library that is supposed to make it easy to run an HTTP server as part of another application."
LICENSE = "LGPLv2.1"
LIC_FILES_CHKSUM = "file://COPYING;md5=9331186f4f80db7da0e724bdd6554ee5"

DEPENDS = "libgcrypt gnutls"

SRC_URI = "ftp://ftp.nluug.nl/pub/gnu/libmicrohttpd/libmicrohttpd-${PV}.tar.gz"
SRC_URI[md5sum] = "ddd583165a80121adc9f3072e67297d0"                                                                                                                                                                                                              
SRC_URI[sha256sum] = "80f48c82fc1b00ad5945a06c810f268d5fa6482eee24af677997a38e41e2606c" 

EXTRA_OECONF = "--enable-https \
  --enable-messages \
  --enable-postprocessor \
  "


inherit autotools lib_package

do_compile_append() {
	sed -i s:-L${STAGING_LIBDIR}::g libmicrohttpd.pc
}
