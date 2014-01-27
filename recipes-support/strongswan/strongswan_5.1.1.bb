DESCRIPTION = "strongSwan is an OpenSource IPsec implementation for the \
Linux operating system."
HOMEPAGE = "http://www.strongswan.org"
SECTION = "console/network"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://COPYING;md5=b234ee4d69f5fce4486a80fdaf4a4263"
DEPENDS = "curl gmp openssl flex-native flex bison-native"
PR = "r5"

SRC_URI = "http://download.strongswan.org/strongswan-${PV}.tar.bz2"
SRC_URI[md5sum] = "e3af3d493d22286be3cd794533a8966a"
SRC_URI[sha256sum] = "fbf2a668221fc4a36a34bdeac2dfeda25b96f572d551df022585177953622406"

EXTRA_OECONF = "--enable-curl --disable-soup --disable-ldap \
        --enable-gmp --disable-mysql --disable-sqlite \
        --enable-openssl --enable-gcrypt --enable-nonce"

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