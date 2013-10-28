DESCRIPTION = "Firmware Image generation"
SECTION = "bsp"
LICENSE = "CLOSED"

DEPENDS += "virtual/kernel"

inherit module-base kernel-module-split externalsrc

addtask make_scripts after do_patch before do_compile
do_make_scripts[lockfiles] = "${TMPDIR}/kernel-scripts.lock"
do_make_scripts[deptask] = "do_populate_sysroot"


#SRC_URI = "file://gen_firmware.sh "

S = "${THISDIR}/apps-pool"

CAV_TOPDIR="${THISDIR}/nitrox-driver-cns3xxx-3.0-pre-release/software"

#do_compile () {
#	cd ${THISDIR}/src
#	oe_runmake
#}

INHIBIT_PACKAGE_STRIP="1"

do_compile() {
	
	unset PARALLEL_MAKE
	unset CFLAGS CPPFLAGS CXXFLAGS LDFLAGS
	
	cd ${THISDIR}/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/driver/linux
	oe_runmake KERNEL_PATH=${STAGING_KERNEL_DIR}   \
		KERNEL_SRC=${STAGING_KERNEL_DIR}    \
		KERNEL_VERSION=${KERNEL_VERSION}    \
		LINUX_VERSION=${KERNEL_VERSION}     \
		CROSS_COMPILE=${TARGET_PREFIX} \
		CC='${KERNEL_CC}' LD=${KERNEL_LD} \
		AR="${KERNEL_AR}" \
		PATCH_UPNAS=n V=s OS=Linux KCFLAGS='-mno-unaligned-access -I../../include' \
		CAV_TOPDIR="${THISDIR}/nitrox-driver-cns3xxx-3.0-pre-release/software" \
		${MAKE_TARGETS}

	cd ${THISDIR}/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/apps/TurboSSL-0.9.8j
	./config no-threads no-asm -DOPENSSL_NO_HW_4758_CCA -DOPENSSL_NO_HW_AEP -DOPENSSL_NO_HW_ATALLA -DOPENSSL_NO_HW_CSWIFT \
		-DOPENSSL_NO_HW_NCIPHER -DOPENSSL_NO_HW_NURON -DOPENSSL_NO_HW_SUREWARE -DOPENSSL_NO_HW_UBSEC cavium  compiler:arm-poky-linux-gnueabi-gcc
#	 perl ./Configure compiler:arm-poky-linux-gnueabi-gcc ${EXTRA_OECONF} shared enable-tlsext --prefix=$useprefix --openssldir=${libdir}/ssl cavium
	sed -i s:/bin/sh:/bin/bash:g Makefile
	make

}

do_install() {
	cd ${THISDIR}/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/driver/linux
	unset CFLAGS CPPFLAGS CXXFLAGS LDFLAGS
	oe_runmake DEPMOD=echo INSTALL_MOD_PATH="${D}" \
		KERNEL_SRC=${STAGING_KERNEL_DIR} \
		KERNEL_PATH=${STAGING_KERNEL_DIR}   \
		KERNEL_VERSION=${KERNEL_VERSION}    \
		LINUX_VERSION=${KERNEL_VERSION}     \
		CC="${KERNEL_CC}" LD="${KERNEL_LD}" \
		CROSS_COMPILE=${TARGET_PREFIX} \
		PATCH_UPNAS=n V=s OS=Linux KCFLAGS='-mno-unaligned-access -I../../include' \
		CAV_TOPDIR="${THISDIR}/nitrox-driver-cns3xxx-3.0-pre-release/software" \
		install
	
	install -d ${D}/nitrox
	install -d ${D}/nitrox/microcode
	install -d ${D}/nitrox/bin
	#microcode binaries
	install -m 755 ${THISDIR}/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/microcode/*.out ${D}/nitrox/microcode
	install -m 755 ${THISDIR}/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/driver/linux/pkp_drv.ko ${D}/nitrox/
	install -m 755 ${THISDIR}/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/utils/csp1_init ${D}/nitrox/bin
	install -m 755 ${THISDIR}/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/utils/test_* ${D}/nitrox/bin
	install -m 755 ${THISDIR}/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/bin/pots.* ${D}/nitrox/bin
}

addtask do_cleansrc before do_cleansrc

do_cleansrc() {
	cd ${THISDIR}/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/driver/linux
		oe_runmake DEPMOD=echo INSTALL_MOD_PATH="${D}" \
		KERNEL_SRC=${STAGING_KERNEL_DIR} \
		KERNEL_PATH=${STAGING_KERNEL_DIR}   \
		KERNEL_VERSION=${KERNEL_VERSION}    \
		LINUX_VERSION=${KERNEL_VERSION}     \
		CC="${KERNEL_CC}" LD="${KERNEL_LD}" \
		CROSS_COMPILE=${TARGET_PREFIX} \
		PATCH_UPNAS=n V=s OS=Linux KCFLAGS='-mno-unaligned-access -I../../include' \
		CAV_TOPDIR="${THISDIR}/nitrox-driver-cns3xxx-3.0-pre-release/software" \
		clean 

	cd ${THISDIR}/apps-pool/nitrox-driver-cns3xxx-3.0-pre-release/software/apps/TurboSSL-0.9.8j
	oe_runmake clean
}

FILES_${PN} = "/nitrox/*"
FILES_${PN}-dbg = "/nitrox/.debug/pkp_drv.ko"

