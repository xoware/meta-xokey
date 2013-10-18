SECTION = "devel"
SUMMARY = "Linux Cryptodev KERNEL MODULE"
DESCRIPTION = "The Cryptodev package contains the kernel /dev/crypto module"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://COPYING;md5=b234ee4d69f5fce4486a80fdaf4a4263"
RCONFLICTS_${PN} = "ocf-linux"

inherit module

PR = "r1"
DEPENDS += "openssl"

SRCREV = "3b2fb637bfe83845b09d338cf57b45176828358e"

SRC_URI = "git://github.com/nmav/cryptodev-linux.git;protocol=git "
#           file://makefile_fixup.patch 
#          file://Add-the-compile-and-install-rules-for-cryptodev-test.patch"

EXTRA_OEMAKE='KERNEL_DIR="${STAGING_KERNEL_DIR}" PREFIX="${D}"'

S = "${WORKDIR}/git"
python () {
	ma = d.getVar("DISTRO_FEATURES", True)
	arch = d.getVar("OVERRIDES", True)

	# the : after the arch is to skip the message on 64b
	if not "multiarch" in ma and ("e5500:" in arch or "e6500:" in arch):
		raise bb.parse.SkipPackage("Building the kernel for this arch requires multiarch to be in DISTRO_FEATURES")

	promote_kernel = d.getVar('BUILD_64BIT_KERNEL')

	if promote_kernel == "1":
		d.setVar('KERNEL_CC_append', ' -m64')
		d.setVar('KERNEL_LD_append', ' -melf64ppc')

	error_qa = d.getVar('ERROR_QA', True)
	if 'arch' in error_qa:
		d.setVar('ERROR_QA', error_qa.replace(' arch', ''))
}

do_compile_append() {
#        oe_runmake -C tests testprogs
	cd tests
	oe_runmake cipher hmac async_cipher 
	cd ..
        cd extras
	${TARGET_PREFIX}gcc -O3 -Wall -fPIC   -c -o eng_cryptodev.o eng_cryptodev.c -I${STAGING_INCDIR}
	${TARGET_PREFIX}gcc --sysroot=${STAGING_DIR_TARGET} -shared -Wl,-soname,libcryptodev.so -lcrypto -o libcryptodev.so eng_cryptodev.o
}

do_install_append() {
#        oe_runmake install_tests
	install -d ${D}/usr
	install -d ${D}/usr/bin
	install -d ${D}/usr/bin/tests_cryptodev
	install -m 0755 tests/cipher ${D}/usr/bin/tests_cryptodev/
	install -m 0755 tests/hmac ${D}/usr/bin/tests_cryptodev/
	install -m 0755 tests/async_cipher ${D}/usr/bin/tests_cryptodev/

#	install -d ${D}/usr
#	install -d ${D}/usr/lib
#	install -d ${D}/usr/lib/ssl
#	install -d ${D}/usr/lib/ssl/engines
#	install -m 0644 extras/libcryptodev.so ${D}/usr/lib/ssl/engines/
}

PACKAGES += "${PN}-tests"
FILES_${PN}-dbg += "${bindir}/tests_cryptodev/.debug"
FILES_${PN}-tests = "${bindir}/tests_cryptodev/*"
