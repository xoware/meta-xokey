require u-boot.inc

DESCRIPTION = "u-boot bootloader for ARM MPU devices"
LICENSE = "GPLv2+"
LIC_FILES_CHKSUM = "file://COPYING;md5=1707d6db1d42237583f50183a5651ecb"

COMPATIBLE_MACHINE = "(sama5d3xek|at91sam9x5ek|exokey)"

# To build u-boot for your machine, provide the following lines in
# your machine config, replacing the assignments as appropriate for
# your machine.
UBOOT_MACHINE_${MACHINE} = "${MACHINE}_nandflash_config"
UBOOT_ENTRYPOINT = "0x20002000"
UBOOT_LOADADDRESS = "0x20002000"

SRCREV = "56ac3aa2cf8070fed0810826eb41024dc030c8a9"

PV = "v2013-at91"
PR = "r1"

SRC_URI = "git://github.com/linux4sam/u-boot-at91.git;branch=master;protocol=git"
SRC_URI += "file://0001-Exokey-has-256M-of-ram.patch \
	file://0002-create-our-entry-in-boards.cfg.patch \
	file://0004-set-default-bootcmd-and-bootargs.-Reduce-timeout-fro.patch "


S = "${WORKDIR}/git"

PACKAGE_ARCH = "${MACHINE_ARCH}"
