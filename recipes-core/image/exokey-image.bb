DESCRIPTION = "A small image just capable of allowing a device to boot."

IMAGE_LINGUAS = " "

LICENSE = "MIT"
DEPENDS = "ek-firmware-native"

inherit core-image deploy

IMAGE_ROOTFS_SIZE = "8192"


# remove not needed ipkg information
ROOTFS_POSTPROCESS_COMMAND += "remove_packaging_data_files ; "

LINUX_VERSION_EXTENSION = "-xoware"


EXOKEY_PKGS = "xokd"
EXOKEY_PKGS += "xoscripts"
EXOKEY_PKGS += "mtd-utils"
EXOKEY_PKGS += "mtd-utils-ubifs"
EXOKEY_PKGS += "mtd-utils-jffs2"
EXOKEY_PKGS += "mtd-utils-misc"
EXOKEY_PKGS += "openssl openssl-engines"
EXOKEY_PKGS += "openvpn"
EXOKEY_PKGS += "iptables"
EXOKEY_PKGS += "cryptodev"
EXOKEY_PKGS += "af-alg-engine"


#Tools for now for debug/testing, remove for production
EXOKEY_PKGS += "tcpdump"
EXOKEY_PKGS += "strace"
EXOKEY_PKGS += "socat"
EXOKEY_PKGS += "cryptodev-tests"


#install all kernel modules
EXOKEY_PKGS += "kernel-modules"

IMAGE_INSTALL = "packagegroup-core-boot ${ROOTFS_PKGMANAGE_BOOTSTRAP} ${CORE_IMAGE_EXTRA_INSTALL}  ${EXOKEY_PKGS}"


LICENSE_FLAGS_WHITELIST += "commercial"
RDEPENDS_kernel-base = ""




do_rootfs_append () {
	EK_VERSION=`cat ${INSTALL_ROOTFS_IPK}/etc/EK_VERSION`
	echo "EK_VERSION = $EK_VERSION"
	gen_firmware.sh ${DEPLOY_DIR_IMAGE} ${EK_VERSION}
	ln -sf EK_Firmware_${EK_VERSION}.bin ${DEPLOY_DIR_IMAGE}/EK_Firmware.bin
	

	echo \[ubifs\] > ubinize.cfg 
	echo mode=ubi >> ubinize.cfg
	echo image=${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.squashfs >> ubinize.cfg 
	echo vol_id=0 >> ubinize.cfg 
	echo vol_type=dynamic >> ubinize.cfg 
	echo vol_name=rootfs >> ubinize.cfg 
	echo vol_flags=autoresize >> ubinize.cfg
	ubinize -o ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.squashfs.ubi ${UBINIZE_ARGS} ubinize.cfg
	ln -sf {IMAGE_NAME}.rootfs.squashfs.ubi  ${DEPLOY_DIR_IMAGE}/rootfs.squashfs.ubi
}