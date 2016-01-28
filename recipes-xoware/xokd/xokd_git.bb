DESCRIPTION = "Daemon to handle device specifc features."
SECTION = "base"
LICENSE = "CLOSED"
DEPENDS = "libgcrypt gnutls curl libmicrohttpd libnl jansson file c-ares libpam"

DEPENDS += "glib-2.0 libnice"

#SRCREV = "HEAD"
SRCREV = "${AUTOREV}"
#PV = "0.1+git${SRCPV}"
PR = "r0"

inherit autotools pkgconfig 

EXTRA_OECONF="--enable-exokey  --with-pam-mods-dir=${base_libdir}/security"
CFLAGS += "-fstack-protector-all -pie -fpie"
LDFLAGS += "-Wl,-z,relro,-z,now"

SRC_URI = "git://github.com/xoware/xokd.git;branch=master;protocol=ssh;user=git"
#SRC_URI = "git:///mnt/xo/guest/xokd;branch=local;protocol=file"


S = "${WORKDIR}/git"

#uncomment this to build code on local PC not on git repo
# inherit externalsrc
#S = "/root/oe-yocto/xokd"
#S = "/home/karl/Work/xoware/xokd"


PACKAGE_ARCH = "${MACHINE_ARCH}"

FILES_${PN} += "${base_libdir}/security/pam_xokd.*"
FILES_${PN}-dbg += "${base_libdir}/security/.debug/pam_xokd.*"
