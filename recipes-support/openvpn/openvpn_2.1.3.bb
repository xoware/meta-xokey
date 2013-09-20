SUMMARY = "A full-featured SSL VPN solution via tun device."
HOMEPAGE = "http://openvpn.sourceforge.net"
SECTION = "console/network"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://COPYING;md5=5aac200199fde47501876cba7263cb0c"
DEPENDS = "lzo openssl"

inherit autotools

SRC_URI = "http://openvpn.net/release/openvpn-${PV}.tar.gz "
#           file://openvpn"

SRC_URI[md5sum] = "7486d3e270ba4b033e311d3e022a0ad7"
SRC_URI[sha256sum] = "5185181df2e6043bd667377bc92e36ea5a5bd7600af209654f109b6403ca5b36"

CFLAGS += "-fno-inline"

# I want openvpn to be able to read password from file (hrw)
EXTRA_OECONF += "--enable-password-save"

do_configure_append() {
    #On my system the openvpn configure is deteting the path of the host ifconfig, not the target..  Manually fix it
    sed -i 's:/bin/ifconfig:/sbin/ifconfig:g' ./config.h
    sed -i 's:/bin/route:/sbin/route:g' ./config.h

}

do_install_append() {
    install -d ${D}/${sysconfdir}/init.d
    install -d ${D}/${sysconfdir}/openvpn
#    install -m 755 ${WORKDIR}/openvpn ${D}/${sysconfdir}/init.d
}

RRECOMMENDS_${PN} = "kernel-module-tun"
