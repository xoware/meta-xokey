DESCRIPTION = "Initial Bootstrap for AT91 ARM MPU"
SECTION = "bootloaders"
LICENSE = "ATMEL"
LIC_FILES_CHKSUM = "file://main.c;endline=27;md5=42f86d2f6fd17d1221c5c651b487a07f"

COMPATIBLE_MACHINE = '(sama5d3xek|at91sam9x5ek|exokey)'

PR = "r1"
SRCREV="69a7c5685c0ad3356b03a023810f59ed67ad5543"
PV="v3.6.0"

SRC_URI =  "git://github.com/linux4sam/at91bootstrap.git;protocol=git"


SRC_URI += "file://exokey_lpddr2.patch \
	file://sclk_rc_osc.patch \
	file://ek1_nf_defconfig "

S = "${WORKDIR}/git"

PARALLEL_MAKE = ""

do_configure() {
	unset LDFLAGS
	unset CFLAGS
	unset CPPFLAGS
	unset ASFLAGS
	make CROSS_COMPILE=${TARGET_PREFIX} ${MACHINE}nf_uboot_defconfig
}

do_configure_sama5d3xek() {
	unset LDFLAGS
	unset CFLAGS
	unset CPPFLAGS
	unset ASFLAGS
	make CROSS_COMPILE=${TARGET_PREFIX} at91sama5d3xeknf_uboot_defconfig
}

do_configure_exokey() {
	unset LDFLAGS
	unset CFLAGS
	unset CPPFLAGS
	unset ASFLAGS
	#make CROSS_COMPILE=${TARGET_PREFIX} sama5d3xeknf_uboot_defconfig
	cp ${WORKDIR}/ek1_nf_defconfig .config
}


do_compile() {
	unset LDFLAGS
	unset CFLAGS
	unset CPPFLAGS
	unset ASFLAGS
	make CROSS_COMPILE=${TARGET_PREFIX}
}

inherit deploy

addtask deploy before do_package after do_install

do_deploy () {
	install -d ${DEPLOY_DIR_IMAGE}
	install ${S}/binaries/${MACHINE}-nandflashboot-uboot-3.6.0.bin ${DEPLOY_DIR_IMAGE}/
}

# Name of binary doesn't follow ${MACHINE} naming convention for the SAMA5D3 series.  Use
# a separate deploy task
do_deploy_sama5d3xek() {
	install -d ${DEPLOY_DIR_IMAGE}
	install ${S}/binaries/at91sama5d3xek-nandflashboot-uboot-3.6.0.bin ${DEPLOY_DIR_IMAGE}/
}

do_deploy_exokey() {
	install -d ${DEPLOY_DIR_IMAGE}
	install ${S}/binaries/sama5d3xek-nandflashboot-uboot-3.6.0.bin ${DEPLOY_DIR_IMAGE}/
}


PACKAGE_ARCH = "${MACHINE_ARCH}"
