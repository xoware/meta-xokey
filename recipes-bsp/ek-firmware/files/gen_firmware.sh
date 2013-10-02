#!/bin/sh
#
# This script writes the firmware binary to the flash MTD device
#
# BUG:  This script needs to be loaded in RAM, so it consumes a lot
# SECURITY:  Loading a shell script, a mallicious user could load a mallicious script as a firmware image
#
DEPLOY_DIR=$1
EK_VERSION=$2
cd $DEPLOY_DIR

FIRMWARE_BIN=./EK_Firmware_${EK_VERSION}.bin
#ROOT_FS_IMG="exokey-image-exokey.squashfs"
ROOT_FS_IMG="exokey-image-exokey.jffs2"
KERNEL_IMG="uImage"

/bin/rm -rf ${FIRMWARE_BIN}

cat << 'EOS' > ${FIRMWARE_BIN}
#!/bin/sh

echo "### Starting FW Update"

if [ $(id -u ) -ne 0 ]; then 
        echo " Please run this script as root"
fi

die() {
  echo "ERROR: $@" 1>&2
#  umount /mnt/tmp >& /dev/null
  exit 1
}

usage() {
  echo "Usage: $0  "  1>&2
  exit 1
}

fwchksum=""

myself=$(pwd)/$0

cfwchksum=$(cat $myself | sed 's/^fwchksum=.*/fwchksum=""/' | md5sum | awk '{print $1}')

if [ $cfwchksum != $fwchksum ]; then
        die "CheckSum mismatch, please reobtain this Package"
fi

chroot_tmp() {
  cd /tmp/
  mkdir -p lib bin sbin usr/bin usr/sbin
  cp -a /lib/libc.* lib
  cp -a /lib/libc-* lib
  cp -a /lib/libgcc* lib
  cp -a /usr/sbin/nandwrite bin/
  cp -a /bin/busybox bin
  cd bin
  for i in $(busybox --list)
  do
      ln -s busybox $i
  done
}

kernel_img() {
echo "### erase kernel"
flash_erase /dev/mtd5 0 0
echo "### writing kernel"
base64 -d << 'LZT_EFS' | nandwrite -p /dev/mtd5 -
EOS
#create this with the following command
base64 ${KERNEL_IMG} >> ${FIRMWARE_BIN}
cat << 'EOS' >>  ${FIRMWARE_BIN}
LZT_EFS
echo "kernel Status =$?"
}

rootfs_img() {
echo "### erase rootfs"
flash_erase /dev/mtd6 0 0
echo "### writing rootfs"
base64 -d << 'LZT_EFS' | nandwrite -p /dev/mtd6 -
EOS
#create this with the following command
base64 ${ROOT_FS_IMG} >> ${FIRMWARE_BIN}
cat << 'EOS' >> ${FIRMWARE_BIN}
LZT_EFS
echo "Rootfs Status =$?"
}


kernel_img
rootfs_img


echo "### reboot"

EOS

chmod 755 ${FIRMWARE_BIN}
cfwchksum=$(cat ${FIRMWARE_BIN} | md5sum | awk '{print $1}')
sed -i "s/^fwchksum=.*/fwchksum=\"$cfwchksum\"/" ${FIRMWARE_BIN}

