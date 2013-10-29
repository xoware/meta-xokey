DESCRIPTION = "Daemon to handle device specifc features."
SECTION = "base"
LICENSE = "CLOSED"
DEPENDS = "libmicrohttpd libnl jansson file gnutls"

SRCREV = "HEAD"
#SRCREV_ = "${AUTOREV}"
#PV = "0.1+git${SRCPV}"
PR = "r0"

inherit autotools pkgconfig 

EXTRA_OECONF="--enable-httpd --enable-mvs"

SRC_URI = "git://github.com/xoware/xokd.git;branch=master;protocol=ssh;user=git"
S = "${WORKDIR}/git"

#uncomment this to build code on local PC not on git repo
# inherit externalsrc
#S = "/home/karl/Work/xoware/xokd"


PACKAGE_ARCH = "${MACHINE_ARCH}"
