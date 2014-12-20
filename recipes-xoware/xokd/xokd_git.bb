DESCRIPTION = "Daemon to handle device specifc features."
SECTION = "base"
LICENSE = "CLOSED"
DEPENDS = "libgcrypt gnutls curl libmicrohttpd libnl jansson file"

DEPENDS += "glib-2.0 libnice"

SRCREV = "master"
#SRCREV_ = "${AUTOREV}"
#PV = "0.1+git${SRCPV}"
PR = "r0"

inherit autotools pkgconfig 

EXTRA_OECONF="--enable-exokey"

SRC_URI = "git://github.com/xoware/xokd.git;branch=master;protocol=ssh;user=git"
#for local shared xokd git work repo shared between en and ek uncomment next 2 lines
#SRCREV = "local"
#SRC_URI = "git:///mnt/xo/guest/xokd;branch=local;protocol=file"
S = "${WORKDIR}/git"

#uncomment this to build code on local PC not on git repo
#inherit externalsrc
#S = "/home/karl/Work/xoware/xokd"


PACKAGE_ARCH = "${MACHINE_ARCH}"
