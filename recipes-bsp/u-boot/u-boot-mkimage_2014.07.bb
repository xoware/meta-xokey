
DESCRIPTION = "U-boot bootloader mkimage tool"
LICENSE = "GPLv2+"
LIC_FILES_CHKSUM = "file://README;beginline=1;endline=22;md5=2687c5ebfd9cb284491c3204b726ea29"
SECTION = "bootloader"


SRCREV = "856093a0b710f8878fc2dc75d53c6df8295e8c85"

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
  ln -sf uboot-mkimage ${D}${bindir}/mkimage
}

BBCLASSEXTEND = "native nativesdk"

