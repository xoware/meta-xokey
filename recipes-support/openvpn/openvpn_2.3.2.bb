SUMMARY = "A full-featured SSL VPN solution via tun device."
HOMEPAGE = "http://openvpn.sourceforge.net"
SECTION = "console/network"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://COPYING;md5=5aac200199fde47501876cba7263cb0c"
DEPENDS = "lzo openssl"

inherit autotools

SRC_URI = "http://swupdate.openvpn.org/community/releases/openvpn-${PV}.tar.gz "
#           file://openvpn"

SRC_URI[md5sum] = "06e5f93dbf13f2c19647ca15ffc23ac1"
SRC_URI[sha256sum] = "20bda3f9debb9a52db262aecddfa4e814050a9404a9106136b7e3b6f7ef36ffc"

CFLAGS += "-fno-inline"

# I want openvpn to be able to read password from file (hrw)
EXTRA_OECONF += "--enable-password-save --disable-plugin-auth-pam ROUTE=/sbin/route IFCONFIG=/sbin/ifconfig"

do_configure_append() {
    #On my system the openvpn configure is deteting the path of the host ifconfig, not the target..  Manually fix it
    sed -i 's:/bin/ifconfig:/sbin/ifconfig:g' ./config.h
    sed -i 's:/bin/route:/sbin/route:g' ./config.h
}

do_install_prepend() {
}

do_install_append() {
#    install -d ${D}/${sysconfdir}/init.d
     install -d ${D}/${sysconfdir}/openvpn
#    install -m 755 ${WORKDIR}/openvpn ${D}/${sysconfdir}/init.d
     echo "libexec = ${libexecdir}"
     echo "datadir = ${datadir}"
}

RRECOMMENDS_${PN} = "kernel-module-tun"

# Exclude debug files from the main packages
FILES_${PN} = "${sysconfdir}/openvpn ${bindir}/* ${sbindir}/* ${datadir}/${BPN} ${libexecdir}/plugins/*"
FILES_${PN}-dbg += "${libexecdir}/plugins/.debug"
