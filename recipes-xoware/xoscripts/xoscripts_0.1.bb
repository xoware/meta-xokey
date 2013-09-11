DESCRIPTION = "Custom setup files"
LICENSE = "CLOSED"
PR = "r1"
DEPENDS = "openssl"

SRC_URI =  "file://profile \
            file://.keep \
            file://firstboot \
            file://rcS \
            file://openssl.cnf \
            file://check_ssl.sh"

PACKAGES = "${PN}"

FILES_${PN} = "/sbin/* ${sysconfdir} /xokcfg /usr"

do_install () {
	install -d ${D}/sbin
	install -d ${D}/etc
	install -d ${D}/etc/init.d
	install -d ${D}/etc/profile.d
	install -d ${D}/xokcfg
	install -d ${D}/usr
	install -d ${D}/usr/lib
	install -d ${D}/usr/lib/ssl
	install -m 0755 ${WORKDIR}/profile ${D}/etc/profile.d/
	install -m 0755 ${WORKDIR}/check_ssl.sh ${D}/sbin/check_ssl.sh
	install -m 0444 ${WORKDIR}/.keep ${D}/xokcfg/
	install -m 0755 ${WORKDIR}/firstboot ${D}/etc/init.d/S10firstboot
	install -m 0755 ${WORKDIR}/rcS ${D}${sysconfdir}/init.d/rcS

	install -m 0444 ${WORKDIR}/openssl.cnf ${D}/usr/lib/ssl/openssl.cnf
	ln -sf  syslog.busybox ${D}/etc/init.d/S00syslog
}
