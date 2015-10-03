SECTION = "devel"
SUMMARY = "openssl engine plugin for AF_ALG crypto interface to kernel"
DESCRIPTION = "crypto interface to kernel"
LICENSE = "BSD"
LIC_FILES_CHKSUM = "file://e_af_alg.c;beginline=4;endline=50;md5=efdaf80e2f803965fef3c9e344c302e9"
RCONFLICTS_${PN} = "ocf-linux"
PACKAGES = "${PN} ${PN}-dbg"

PR = "r1"
DEPENDS += "openssl"

SRCREV = "1851bbb010c38878c83729be844f168192059189"

#SRC_URI = "git://git.carnivore.it/users/common/af_alg.git;protocol=git "
SRC_URL = "git://github.com/xoware/af_ag;protocol=git"
S = "${WORKDIR}/git"

#inherit externalsrc
#S = "/home/karl/Work/af_alg"


PACKAGE_ARCH = "${MACHINE_ARCH}"

FILES_${PN} = "/usr/lib/engines/libaf_alg.so "
FILES_${PN}-dbg += "/usr/lib/engines/.debug/libaf_alg.so"

do_compile() {
	LDFLAGS="--hash-style=gnu --as-needed"
	oe_runmake
#	${TARGET_PREFIX}gcc -Os -Wall -fPIC   -c -o e_af_alg.o e_af_alg.c -I${STAGING_INCDIR}
#	${TARGET_PREFIX}gcc --sysroot=${STAGING_DIR_TARGET} -shared -Wl,-soname,libaf_alg.so -lcrypto -o libaf_alg.so e_af_alg.o
}

do_install() {
	install -d ${D}/usr
	install -d ${D}/usr/lib
	install -d ${D}/usr/lib/engines
	install -d ${D}/usr/lib/engines/
	install -d ${D}/usr/lib/engines/.debug
#	oe_libinstall -so libaf_alg.so ${D}/usr/lib/engines/
#FIXME strip
	install -m 0644 libaf_alg.so ${D}/usr/lib/engines/
	install -m 0644 libaf_alg.so ${D}/usr/lib/engines/.debug/
}


