
# This branch is now maintained with fixes,
# though we will use a particular commit via SRCREV.
KBRANCH = "linux-3.6.9-at91"

#add recipie that has our initramfs



# path to get defconfig from
FILESEXTRAPATHS_prepend := "${THISDIR}/linux-3.6:" 

SRC_URI += "file://0001-dma-at91-avoid-possible-deadlock-in-atc_tx_status.patch \ 
	file://0001-crypto-scatterwalk-Set-the-chain-pointer-indication-.patch \
	file://0001-crypto-scatterwalk-Use-sg_chain_ptr-on-chain-entries.patch \
	file://0001-cryto-atmel-sha-add-HMAC-ahash_alg.patch \
	file://no-usb-vbus-sense.patch \
	file://clocksource-debug.patch \
	file://usb_eth_rndis_xoware.patch "
#	file://gpio_sysfs.cfg "


LINUX_KERNEL_TYPE ?= "standard"
LINUX_VERSION_EXTENSION = "-xoware"

SRCREV="e5fb8621b409acf95c64d543102e2c89aa006b42"
SRCREV_machine="e5fb8621b409acf95c64d543102e2c89aa006b42"
PV = "${LINUX_VERSION}+${SRCREV}"


#add exokey machine
COMPATIBLE_MACHINE = "(sama5d3xek|at91sam9x5ek|exokey)"

#disable parallel make install incase this fixes race
PARALLEL_MAKEINST=""
