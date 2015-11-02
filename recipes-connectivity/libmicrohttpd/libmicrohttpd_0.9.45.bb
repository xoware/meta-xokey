DESCRIPTION = "A small C library that is supposed to make it easy to run an HTTP server as part of another application"
HOMEPAGE = "http://www.gnu.org/software/libmicrohttpd/"
LICENSE = "LGPL-2.1+"
LIC_FILES_CHKSUM = "file://COPYING;md5=9331186f4f80db7da0e724bdd6554ee5"
SECTION = "net"
DEPENDS = "libgcrypt gnutls file"

SRC_URI = "http://ftp.gnu.org/gnu/libmicrohttpd/${BPN}-${PV}.tar.gz"
SRC_URI[md5sum] = "21b41d781384b85233dbce47582552ca"
SRC_URI[sha256sum] = "1075def48da9327be22441f4a3460d24159fae2bf4bcfb4ab6e7ca5e95e54a69"

inherit autotools lib_package

# disable spdy, because it depends on openssl
EXTRA_OECONF += "--disable-static --with-gnutls=${STAGING_LIBDIR}/../ --disable-spdy \
 --enable-https \
  --enable-messages \
  --enable-postprocessor \
  "


PACKAGECONFIG ?= "curl"
PACKAGECONFIG_append_class-target = "\
        ${@base_contains('DISTRO_FEATURES', 'largefile', 'largefile', '', d)} \
"
PACKAGECONFIG[largefile] = "--enable-largefile,--disable-largefile,,"
PACKAGECONFIG[curl] = "--enable-curl,--disable-curl,curl,"


do_configure_prepend() {
	autoreconf -fi ${S}
	cd ${S}
	aclocal -I m4 --install
#	oe_runconf
	cd ${B}
}

do_compile_append() {
	sed -i s:-L${STAGING_LIBDIR}::g libmicrohttpd.pc
}


