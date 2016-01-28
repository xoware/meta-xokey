require u-boot.inc

# To build u-boot for your machine, provide the following lines in your machine
# config, replacing the assignments as appropriate for your machine.
# UBOOT_MACHINE = "omap3_beagle_config"
# UBOOT_ENTRYPOINT = "0x80008000"
# UBOOT_LOADADDRESS = "0x80008000"

LICENSE = "GPLv2+"
LIC_FILES_CHKSUM = "file://README;beginline=1;endline=22;md5=2687c5ebfd9cb284491c3204b726ea29"


DEPENDS = "dtc-native"
SRCREV = "4f28dd0d23fbe16db1a08bc48434c7e0caa2f54c"
PV = "v2014.07-at91"
PR = "r2"

COMPATIBLE_MACHINE = "(sama5d3xek|at91sam9x5ek|sama5d3_xplained|exokey)"

# To build u-boot for your machine, provide the following lines in
# your machine config, replacing the assignments as appropriate for
# your machine.
UBOOT_MACHINE ?= "${MACHINE}_nandflash_config"
UBOOT_ENTRYPOINT ?= "0x20002000"
UBOOT_LOADADDRESS ?= "0x20002000"

UBOOT_SUFFIX = "bin"
UBOOT_BINARY = "u-boot-dtb.${UBOOT_SUFFIX}"


SRC_URI = "git://github.com/xoware/ek-uboot-at91.git;branch=exokey_v2014.07;protocol=ssh;user=git"
S = "${WORKDIR}/git"

PACKAGE_ARCH = "${MACHINE_ARCH}"


do_compile_prepend() {
	dtc -O dtb --out arch/arm/dts/exokey-device-tree.dtb arch/arm/dts/exokey-device-tree.dts 
}

