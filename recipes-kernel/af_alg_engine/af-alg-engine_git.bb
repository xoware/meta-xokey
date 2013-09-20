SECTION = "devel"
SUMMARY = "openssl engine plugin for AF_ALG crypto interface to kernel"
DESCRIPTION = "crypto interface to kernel"
LICENSE = "BSD"
LIC_FILES_CHKSUM = "file://e_af_alg.c;beginline=4;endline=50;md5=0c466e83f15c004c1f46d3ed192eacf6"
RCONFLICTS_${PN} = "ocf-linux"
PACKAGES = "${PN} ${PN}-dbg"

PR = "r1"
DEPENDS += "openssl"

SRCREV = "7b13512edbd77c35d20edb4e53d5d83eeaf05d52"

SRC_URI = "git://git.carnivore.it/users/common/af_alg.git;protocol=git "


S = "${WORKDIR}/git"

FILES_${PN} = "/usr/lib/engines/libaf_alg.so "
FILES_${PN}-dbg += "/usr/lib/engines/.debug/libaf_alg.so"

do_compile() {
	${TARGET_PREFIX}gcc -Os -Wall -fPIC   -c -o e_af_alg.o e_af_alg.c -I${STAGING_INCDIR}
	${TARGET_PREFIX}gcc --sysroot=${STAGING_DIR_TARGET} -shared -Wl,-soname,libaf_alg.so -lcrypto -o libaf_alg.so e_af_alg.o
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


