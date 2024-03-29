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
#require recipes-kernel/linux/linux-yocto.inc

LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://COPYING;md5=d7810fab7487fb0aad327b76f1be7cd7"
DEFAULT_PREFERENCE = "-1"
# Note: 3.10.X series is a long term kernel (karl)
# https://www.kernel.org/category/releases.html
LINUX_VERSION = "3.10.11"
LINUX_VERSION_EXTENSION ?= "-custom"
KBRANCH ?= "linux-3.10.y"
META = "meta"

# Override SRC_URI in a bbappend file to point at a different source
# tree if you do not want to build from Linus' tree.
#SRC_URI = "git://github.com/linux4sam/linux-at91.git;protocol=git;branch=${KBRANCH};nocheckout=1"
#SRC_URI = "git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git;tag=v${LINUX_VERSION}"
SRC_URI = "git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git;branch=${KBRANCH}"


#SRC_URI = "https://www.kernel.org/pub/linux/kernel/v3.x/linux-${LINUX_VERSION}.tar.xz"
SRC_URI += "file://defconfig"




# Override SRCREV to point to a different commit in a bbappend file to
# build a different release of the Linux kernel.
# tag: v3.4 76e10d158efb6d4516018846f60c2ab5501900bc
#3.10.11
#SRCREV="85cdabba08d484bdcc4b25f0bbc23ac60c75aa5b"
SRCREV="v3.10.11"


#PV = "${LINUX_VERSION}+${SRCREV}"
PV = "${LINUX_VERSION}"

PR = "r1"

S = "${WORKDIR}/git"
EXTRA_OEMAKE = "${PARALLEL_MAKE}"

# Override COMPATIBLE_MACHINE to include your machine in a bbappend
# file. Leaving it empty here ensures an early explicit build failure.
COMPATIBLE_MACHINE = "(sama5d3xek|at91sam9x5ek|exokey)"

