DESCRIPTION = "A small image just capable of allowing a device to boot."

IMAGE_LINGUAS = " "

LICENSE = "MIT"
DEPENDS = "ek-firmware-native"

inherit core-image deploy

IMAGE_ROOTFS_SIZE = "8192"


# remove not needed ipkg information
ROOTFS_POSTPROCESS_COMMAND += "remove_packaging_data_files ; "

LINUX_VERSION_EXTENSION = "-xoware"
PREFERRED_VERSION_linux-yocto = "3.6.%"

MVS_PKGS = "xokd"
MVS_PKGS += "xoscripts"
MVS_PKGS += "mtd-utils"
MVS_PKGS += "mtd-utils-ubifs"
MVS_PKGS += "mtd-utils-jffs2"
MVS_PKGS += "mtd-utils-misc"
#MVS_PKGS += "openssl openssl-engines"
#MVS_PKGS += "openvpn"
MVS_PKGS += "iptables"
#MVS_PKGS += "cryptodev"
MVS_PKGS += "af-alg-engine"
MVS_PKGS += "cavium-nitrox"

#Tools for now for debug/testing, remove for production
MVS_PKGS += "tcpdump"
MVS_PKGS += "strace"
MVS_PKGS += "socat"
#MVS_PKGS += "cryptodev-tests"

MVS_PKGS += "libnl-route libnl-genl"


#install all kernel modules
MVS_PKGS += "kernel-modules"

IMAGE_INSTALL = "packagegroup-core-boot ${ROOTFS_PKGMANAGE_BOOTSTRAP} ${CORE_IMAGE_EXTRA_INSTALL}  ${MVS_PKGS}"


LICENSE_FLAGS_WHITELIST += "commercial"
RDEPENDS_kernel-base = ""

INITRAMFS_FSTYPES = "cpio.gz"


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
#	echo vol_flags=autoresize >> ubinize.cfg
	ubinize -o ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.squashfs.ubi ${UBINIZE_ARGS} ubinize.cfg
	ln -sf ${IMAGE_NAME}.rootfs.squashfs.ubi  ${DEPLOY_DIR_IMAGE}/rootfs.squashfs.ubi
	
	#generate firmware image for update in linux UI
	xomkimage ${DEPLOY_DIR_IMAGE}/uImage:mtd:5:0:kernel  ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.squashfs:ubivol:0:0:new_rootfs  > ${DEPLOY_DIR_IMAGE}/firmware_${EK_VERSION}.img
	ln -sf ${DEPLOY_DIR_IMAGE}/firmware_${EK_VERSION}.img ${DEPLOY_DIR_IMAGE}/firmware.img
}