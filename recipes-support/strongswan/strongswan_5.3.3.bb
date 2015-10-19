DESCRIPTION = "strongSwan is an OpenSource IPsec implementation for the \
Linux operating system."
HOMEPAGE = "http://www.strongswan.org"
SECTION = "console/network"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://COPYING;md5=b234ee4d69f5fce4486a80fdaf4a4263"
DEPENDS = "curl gmp openssl flex-native flex bison-native"
PR = "r5"

SRC_URI = "http://download.strongswan.org/strongswan-${PV}.tar.bz2"
SRC_URI[md5sum] = "5a25f3d1c31a77ef44d14a2e7b3eaad0"
SRC_URI[sha256sum] = "39d2e8f572a57a77dda8dd8bdaf2ee47ad3cefeb86bbb840d594aa75f00f33e2"

EXTRA_OECONF = "--enable-curl --disable-soup --disable-ldap \
        --enable-gmp --disable-mysql --disable-sqlite \
        --enable-openssl --enable-gcrypt --enable-nonce \
	--enable-socket-dynamic "

#EXTRA_OECONF += "${@base_contains('DISTRO_FEATURES', 'systemd', '--with-systemdsystemunitdir=${systemd_unitdir}/system/', '--without-systemdsystemunitdir', d)}"

inherit autotools

RRECOMMENDS_${PN} = "kernel-module-ipsec"

PACKAGES += "${PN}-plugins"
FILES_${PN} += "${libdir}/ipsec/lib*${SOLIBS}"
FILES_${PN}-dev += "${libdir}/ipsec/lib*${SOLIBSDEV} ${libdir}/ipsec/*.la"
FILES_${PN}-staticdev += "${libdir}/ipsec/*.a"
FILES_${PN}-dbg += "${libdir}/ipsec/.debug ${libdir}/ipsec/plugins/.debug ${libexecdir}/ipsec/.debug"
FILES_${PN}-plugins += "${libdir}/ipsec/plugins/*"

INSANE_SKIP_${PN}-plugins = "staticdev"

#RPROVIDES_${PN} += "${PN}-systemd"
#RREPLACES_${PN} += "${PN}-systemd"
#RCONFLICTS_${PN} += "${PN}-systemd"
#SYSTEMD_SERVICE_${PN} = "${PN}.service"


do_install_append() {
    rm -f ${D}${sysconfdir}/ipsec.conf
    rm -f ${D}${sysconfdir}/strongswan.conf
    rm -rf ${D}${sysconfdir}/ipsec.d
    ln -sf /tmp/ipsec.conf ${D}/etc/ipsec.conf
    ln -sf /tmp/ipsec.secrets ${D}/etc/ipsec.secrets
    ln -sf /tmp/strongswan.conf ${D}/etc/strongswan.conf
    ln -sf /tmp/ipsec.d ${D}/etc/ipsec.d
}
