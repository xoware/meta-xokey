DESCRIPTION = "A small image just capable of allowing a device to boot."

IMAGE_LINGUAS = " "

LICENSE = "MIT"

inherit core-image

IMAGE_ROOTFS_SIZE = "8192"

# remove not needed ipkg informations
ROOTFS_POSTPROCESS_COMMAND += "remove_packaging_data_files ; "

LINUX_VERSION_EXTENSION = "-xoware"


EXOKEY_PKGS = "xokd"
EXOKEY_PKGS += "xoscripts"
EXOKEY_PKGS += "mtd-utils"
EXOKEY_PKGS += "mtd-utils-ubifs"
EXOKEY_PKGS += "mtd-utils-jffs2"
EXOKEY_PKGS += "openssl"
EXOKEY_PKGS += "openvpn"
#install all kernel modules
EXOKEY_PKGS += "kernel-modules"

IMAGE_INSTALL = "packagegroup-core-boot ${ROOTFS_PKGMANAGE_BOOTSTRAP} ${CORE_IMAGE_EXTRA_INSTALL}  ${EXOKEY_PKGS}"


LICENSE_FLAGS_WHITELIST += "commercial"
RDEPENDS_kernel-base = ""