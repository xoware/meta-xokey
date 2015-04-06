DESCRIPTION = "Custom setup files"
LICENSE = "CLOSED"
PR = "r1"
DEPENDS = "openssl"

SRC_URI =  "file://profile \
            file://.keep \
            file://firstboot \
            file://inittab \
            file://storage \
            file://openvpn.up.sh \
            file://openvpn.down.sh \
            file://rcS \
            file://S80xokd \
            file://coredumps \
            file://ca-certificates.crt \
            file://vpex-ca-certs.pem \
            file://xokd-watcher.sh \
            file://check_ssl.sh"

PACKAGES = "${PN}"

FILES_${PN} = "/sbin/* ${sysconfdir} /xokcfg /usr /storage"

do_install () {
	install -d ${D}/sbin
	install -d ${D}/etc
	install -d ${D}/etc/openvpn
	install -d ${D}/etc/init.d
	install -d ${D}/etc/profile.d
	install -d ${D}/etc/ssl
	install -d ${D}/etc/ssl/certs
	install -d ${D}/xokcfg
	install -d ${D}/storage
	install -d ${D}/usr
	install -d ${D}/usr/bin
	install -d ${D}/usr/lib
	install -d ${D}/usr/lib/ssl
	install -m 0755 ${WORKDIR}/profile ${D}/etc/profile.d/
	install -m 0755 ${WORKDIR}/check_ssl.sh ${D}/sbin/check_ssl.sh
	install -m 0444 ${WORKDIR}/.keep ${D}/xokcfg/
	install -m 0444 ${WORKDIR}/.keep ${D}/storage/
	install -m 0755 ${WORKDIR}/firstboot ${D}/etc/init.d/S10firstboot
	install -m 0755 ${WORKDIR}/storage ${D}/etc/init.d/S20storage
	install -m 0755 ${WORKDIR}/coredumps ${D}/etc/init.d/S25coredumps
	install -m 0755 ${WORKDIR}/rcS ${D}${sysconfdir}/init.d/rcS
	install -m 0755 ${WORKDIR}/S80xokd ${D}${sysconfdir}/init.d/S80xokd
	install -m 0755 ${WORKDIR}/ca-certificates.crt ${D}${sysconfdir}/ssl/certs/
	install -m 0755 ${WORKDIR}/vpex-ca-certs.pem ${D}${sysconfdir}/ssl/certs/
	install -m 0755 ${WORKDIR}/xokd-watcher.sh  ${D}/usr/bin
	install -m 0644 ${WORKDIR}/inittab ${D}${sysconfdir}/
#	install -m 0755 ${WORKDIR}/openvpn.up.sh ${D}${sysconfdir}/openvpn/
#	install -m 0755 ${WORKDIR}/openvpn.down.sh ${D}${sysconfdir}/openvpn/
#	install -m 0444 ${WORKDIR}/openssl.cnf ${D}/usr/lib/ssl/openssl.cnf
	ln -sf  syslog.busybox ${D}/etc/init.d/S00syslog
	ln -sf  /tmp/resolv.conf ${D}/etc/resolv.conf
	echo 1.0.`date +%Y%m%d%H%M` > ${D}/etc/XO_VERSION

}
