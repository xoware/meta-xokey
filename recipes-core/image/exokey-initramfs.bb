DESCRIPTION = "A small image just capable of allowing a device to boot."

IMAGE_LINGUAS = " "

LICENSE = "MIT"
DEPENDS = "ek-firmware-native"

inherit image

IMAGE_ROOTFS_SIZE = "8192"

# remove not needed ipkg information
ROOTFS_POSTPROCESS_COMMAND += "remove_packaging_data_files ; "

LINUX_VERSION_EXTENSION = "-xoware"

IMAGE_INSTALL = "busybox xoscripts-initramfs"


LICENSE_FLAGS_WHITELIST += "commercial"
RDEPENDS_kernel-base = ""


KERNEL_IMAGETYPE = "uImage"
IMAGE_FSTYPES = "cpio cpio.gz"

#SRC_URI = "file://init "
#
#do_install_append() {
#	install -m 755 ${WORKDIR}/init ${IMAGE_ROOTFS}/
#}

do_rootfs_append () {
	
#	echo "EK_VERSION = $EK_VERSION"
}