#!/bin/sh

DEPLOY_DIR=$1
EK_VERSION=$2
cd $DEPLOY_DIR

FIRMWARE_BIN=./EK_Firmware_${EK_VERSION}.bin
ROOT_FS_IMG="exokey-image-exokey.squashfs"
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


kernel_img() {
base64 -d << 'LZT_EFS' | nandwrite /dev/mtd5 -
EOS
#create this with the following command
base64 ${KERNEL_IMG} >> ${FIRMWARE_BIN}
cat << 'EOS' >>  ${FIRMWARE_BIN}
LZT_EFS
echo "kernel Status =$?"
}

rootfs_img() {
base64 -d << 'LZT_EFS' | nandwrite /dev/mtd6 -
EOS
#create this with the following command
base64 ${ROOT_FS_IMG} >> ${FIRMWARE_BIN}
cat << 'EOS' >> ${FIRMWARE_BIN}
LZT_EFS
echo "Rootfs Status =$?"
}

echo "### writing kernel"
kernel_img
echo "### writing rootfs"
rootfs_img


echo "### reboot"

EOS

chmod 755 ${FIRMWARE_BIN}
cfwchksum=$(cat ${FIRMWARE_BIN} | md5sum | awk '{print $1}')
sed -i "s/^fwchksum=.*/fwchksum=\"$cfwchksum\"/" ${FIRMWARE_BIN}

