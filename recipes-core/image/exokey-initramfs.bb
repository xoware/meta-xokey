DESCRIPTION = "A small image just capable of allowing a device to boot."

IMAGE_LINGUAS = " "

LICENSE = "MIT"
DEPENDS = "ek-firmware-native"

inherit core-image

IMAGE_ROOTFS_SIZE = "8192"

#TODO test this with 1
BUSYBOX_SPLIT_SUID = "0"

# remove not needed ipkg information
#ROOTFS_POSTPROCESS_COMMAND += "remove_packaging_data_files ; "

LINUX_VERSION_EXTENSION = "-xoware"

PACKAGE_INSTALL = "busybox xoscripts-initramfs mtd-utils mtd-utils-ubifs"
PACKAGE_INSTALL += " kernel-module-atmel-usba-udc "
PACKAGE_INSTALL += " kernel-module-usb-common "
PACKAGE_INSTALL += " kernel-module-g-ether "

#contains sigcheck util
PACKAGE_INSTALL += " xomkimage "


LICENSE_FLAGS_WHITELIST += "commercial "
LICENSE_FLAGS_WHITELIST += "CLOSED "
#RDEPENDS_kernel-base = ""

KERNEL_IMAGETYPE = "uImage"
IMAGE_FSTYPES = "cpio.gz"
IMAGE_DEVICE_TABLES = "files/ek_device_table.txt"


do_rootfs_append () {
	
#	echo "XO_VERSION = $XO_VERSION"
}
