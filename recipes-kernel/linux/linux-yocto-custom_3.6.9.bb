# linux-yocto-custom.bb:
#
#   An example kernel recipe that uses the linux-yocto and oe-core
#   kernel classes to apply a subset of yocto kernel management to git
#   managed kernel repositories.
#
#   To use linux-yocto-custom in your layer, create a
#   linux-yocto-custom.bbappend file containing at least the following
#   lines:
#
#     FILESEXTRAPATHS_prepend := "${THISDIR}/${PN}:"
#     COMPATIBLE_MACHINE_yourmachine = "yourmachine"
#
#   You must also provide a Linux kernel configuration. The most direct
#   method is to copy your .config to files/defconfig in your layer,
#   in the same directory as the bbappend and add file://defconfig to
#   your SRC_URI.
#
#   To use the yocto kernel tooling to generate a BSP configuration
#   using modular configuration fragments, see the yocto-bsp and
#   yocto-kernel tools documentation.
#
# Warning:
#
#   Building this example without providing a defconfig or BSP
#   configuration will result in build or boot errors. This is not a
#   bug.
#
#
# Notes:
#
#   patches: patches can be merged into to the source git tree itself,
#            added via the SRC_URI, or controlled via a BSP
#            configuration.
#
#   example configuration addition:
#            SRC_URI += "file://smp.cfg"
#   example patch addition (for kernel v3.4 only):
#            SRC_URI += "file://0001-linux-version-tweak.patch
#   example feature addition (for kernel v3.4 only):
#            SRC_URI += "file://feature.scc"
#

inherit kernel
require recipes-kernel/linux/linux-yocto.inc
LINUX_VERSION ?= "3.6.9"
LINUX_VERSION_EXTENSION ?= "-custom"
KBRANCH ?= "3.6.9-at91"
KBRANCH = "linux-3.6.9-at91"

# Override SRC_URI in a bbappend file to point at a different source
# tree if you do not want to build from Linus' tree.
#SRC_URI = "git://github.com/linux4sam/linux-at91.git;protocol=git;branch=${KBRANCH};nocheckout=1"
SRC_URI = "git://github.com/karlhiramoto/linux-at91;protocol=git;branch=${KBRANCH}"
SRC_URI += "file://defconfig"

SRC_URI += "file://0001-dma-at91-avoid-possible-deadlock-in-atc_tx_status.patch \ 
	file://0001-crypto-scatterwalk-Set-the-chain-pointer-indication-.patch \
	file://0001-crypto-scatterwalk-Use-sg_chain_ptr-on-chain-entries.patch \
	file://0001-cryto-atmel-sha-add-HMAC-ahash_alg.patch \
	file://add-compiler-gcc5.h.patch \
	file://no-usb-vbus-sense.patch \
	file://clocksource-debug.patch \
	file://ignore_mtd_readonly.patch \
	file://fix-build-on-newer-perl-versions.patch \
	file://usb_eth_rndis_xoware.patch "
#	file://gpio_sysfs.cfg "




SRCREV="e5fb8621b409acf95c64d543102e2c89aa006b42"
SRCREV_machine="e5fb8621b409acf95c64d543102e2c89aa006b42"
PV = "${LINUX_VERSION}+${SRCREV}"


PR = "r1"

# Override COMPATIBLE_MACHINE to include your machine in a bbappend
# file. Leaving it empty here ensures an early explicit build failure.
COMPATIBLE_MACHINE = "(sama5d3xek|at91sam9x5ek|exokey)"
KMACHINE="sama5d3"


# This branch is now maintained with fixes,
# though we will use a particular commit via SRCREV.


# path to get defconfig from
FILESEXTRAPATHS_prepend := "${THISDIR}/linux-3.6:" 


LINUX_KERNEL_TYPE ?= "standard"
LINUX_VERSION_EXTENSION = "-xoware"

#disable parallel make install incase this fixes race
PARALLEL_MAKEINST=""

do_configure_prepend(){
	echo "IN CONFIGURE PREPEND"
	echo "B = ${B}"
	echo "S = ${S}"
	#cp -v ${B}/../defconfig ${B}/.config
}



