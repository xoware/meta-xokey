DESCRIPTION = "Daemon to handle device specifc features."
SECTION = "base"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://COPYING;md5=26e719a279edbfa8b25e9ccfead36d85"
DEPENDS = "libmicrohttpd libnl jansson file"

SRCREV = "HEAD"
#SRCREV_ = "${AUTOREV}"
#PV = "0.1+git${SRCPV}"
PR = "r0"

SRC_URI = "git://github.com/xoware/xokd.git;branch=master;protocol=ssh;user=git"

S = "${WORKDIR}/git"

PACKAGE_ARCH = "${MACHINE_ARCH}"

inherit autotools pkgconfig

#inherit update-rc.d
#INITSCRIPT_NAME = "xokd"
#INITSCRIPT_PARAMS = "start 99 5 2 . stop 20 0 1 6 ."
