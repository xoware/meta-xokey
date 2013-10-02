DESCRIPTION = "Custom setup files"
LICENSE = "CLOSED"
PR = "r1"

SRC_URI =  "file://init"

PACKAGES = "${PN}"

FILES_${PN} = "/"

do_install () {
	install -d ${D}/

	install -m 0755 ${WORKDIR}/init ${D}/
}
