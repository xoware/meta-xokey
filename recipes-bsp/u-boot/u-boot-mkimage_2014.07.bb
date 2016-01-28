
DESCRIPTION = "U-boot bootloader mkimage tool"
LICENSE = "GPLv2+"
LIC_FILES_CHKSUM = "file://README;beginline=1;endline=22;md5=2687c5ebfd9cb284491c3204b726ea29"
SECTION = "bootloader"


SRCREV = "4f28dd0d23fbe16db1a08bc48434c7e0caa2f54c"

PV = "v2014.07-at91"
PR = "r1"

SRC_URI = "git://github.com/xoware/ek-uboot-at91.git;branch=exokey_v2014.07;protocol=ssh;user=git"

S = "${WORKDIR}/git"

EXTRA_OEMAKE = 'HOSTCC="${CC}" HOSTLD="${LD}" HOSTLDFLAGS="${LDFLAGS}" HOSTSTRIP=true'

do_compile () {
  oe_runmake sandbox_config
  oe_runmake tools
}

do_install () {
  install -d ${D}${bindir}
  install -m 0755 tools/mkimage ${D}${bindir}/uboot-mkimage
  install -m 0755 tools/mkenvimage ${D}${bindir}/uboot-mkenvimage
  ln -sf uboot-mkimage ${D}${bindir}/mkimage
  ln -sf uboot-mkenvimage ${D}${bindir}/mkenvimage
}

BBCLASSEXTEND = "native nativesdk"

