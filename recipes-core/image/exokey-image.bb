DESCRIPTION = "A small image just capable of allowing a device to boot."

IMAGE_LINGUAS = " "

LICENSE = "MIT"
DEPENDS = "ek-firmware-native xomkimage-native u-boot-mkimage-native"

inherit core-image deploy

IMAGE_ROOTFS_SIZE = "8192"


# remove not needed ipkg information
ROOTFS_POSTPROCESS_COMMAND += "remove_packaging_data_files ; "

LINUX_VERSION_EXTENSION = "-xoware"
PREFERRED_VERSION_linux-yocto = "3.6.%"

EXOKEY_PKGS = "xokd"
EXOKEY_PKGS += "xoscripts"
EXOKEY_PKGS += "mtd-utils"
EXOKEY_PKGS += "mtd-utils-ubifs"
EXOKEY_PKGS += "mtd-utils-jffs2"
EXOKEY_PKGS += "mtd-utils-misc"
EXOKEY_PKGS += "openssl openssl-engines"
#EXOKEY_PKGS += "openvpn"
EXOKEY_PKGS += "iptables"
#EXOKEY_PKGS += "cryptodev"
EXOKEY_PKGS += "af-alg-engine"
EXOKEY_PKGS += "strongswan strongswan-plugins"

#build uboot
EXOKEY_PKGS += "ek-uboot-at91"

#Tools for now for debug/testing, remove for production
EXOKEY_PKGS += "tcpdump"
EXOKEY_PKGS += "strace"
EXOKEY_PKGS += "iperf"
EXOKEY_PKGS += "socat"
EXOKEY_PKGS += "memtester"
#EXOKEY_PKGS += "cryptodev-tests"
#EXOKEY_PKGS += "gdb"
EXOKEY_PKGS += "libnl-route libnl-genl"
#EXOKEY_PKGS += "oprofile"


#install all kernel modules
EXOKEY_PKGS += "kernel-modules"

IMAGE_INSTALL = "packagegroup-core-boot ${ROOTFS_PKGMANAGE_BOOTSTRAP} ${CORE_IMAGE_EXTRA_INSTALL}  ${EXOKEY_PKGS}"

#contains sigcheck util only needed in initramfs,  here for testing
PACKAGE_INSTALL += " xomkimage "

LICENSE_FLAGS_WHITELIST += "commercial"
LICENSE_FLAGS_WHITELIST += "CLOSED"
RDEPENDS_kernel-base = ""

INITRAMFS_FSTYPES = "cpio.gz"
INITRAMFS_IMAGE = "exokey-initramfs"



do_rootfs_append () {
	XO_VERSION=`cat ${INSTALL_ROOTFS_IPK}/etc/XO_VERSION`
	echo "XO_VERSION = $XO_VERSION"

	#sign squashfs
	cp ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.squashfs ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.squashfs.signed
	xosignappend -f ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.squashfs.signed

	#generate ubi file for usage with sam-ba
	SQUASH_SIZE=`stat -c %s ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.squashfs.signed`
	echo "Squash size = ${SQUASH_SIZE}"
	echo \[ubifs\] > ubinize.cfg 
	echo mode=ubi >> ubinize.cfg
	echo image=${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.squashfs.signed >> ubinize.cfg 
	echo vol_id=0 >> ubinize.cfg 
	echo vol_type=dynamic >> ubinize.cfg 
	echo vol_name=rootfs >> ubinize.cfg 
	echo vol_size=${SQUASH_SIZE} >> ubinize.cfg 
#NOTE do NOT specify autoresize or it will take up the whole device
#	echo vol_flags=autoresize >> ubinize.cfg
	ubinize -o ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.squashfs.ubi ${UBINIZE_ARGS} ubinize.cfg
	ln -sf ${IMAGE_NAME}.rootfs.squashfs.ubi  ${DEPLOY_DIR_IMAGE}/rootfs.squashfs.ubi

	#sign linux and create uboot FIT image
	cd ${DEPLOY_DIR_IMAGE}
	uboot-mkimage -D "-I dts -O dtb -p 2000" -k ${STAGING_ETCDIR_NATIVE}/keys -f sign_kernel_config_fit.its -r kernel.fit

	#generate firmware image for update in linux UI
	xomkimage ${DEPLOY_DIR_IMAGE}/zImage-initramfs-exokey.bin:mtd:5:0:mtd5:uImage  ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.squashfs.signed:ubivol:0:0:ubi0:new_rootfs  > ${DEPLOY_DIR_IMAGE}/EK_firmware_${XO_VERSION}_unsigned.img
	xomkimage_v1 ExoKey_v1 $XO_VERSION 1.0.20140801 ${DEPLOY_DIR_IMAGE}/u-boot-dtb.bin:mtd:1:0:mtd1:uBoot  ${DEPLOY_DIR_IMAGE}/kernel.fit:mtd:5:0:mtd5:uImage  ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.rootfs.squashfs.signed:ubivol:0:0:ubi0:new_rootfs  > ${DEPLOY_DIR_IMAGE}/EK_firmware_${XO_VERSION}.img
	ln -sf ${DEPLOY_DIR_IMAGE}/EK_firmware_${XO_VERSION}.img ${DEPLOY_DIR_IMAGE}/EK_firmware.img
}
