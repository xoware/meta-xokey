DESCRIPTION = "Firmware Image generation"
SECTION = "bsp"
LICENSE = "CLOSED"


inherit native
SRC_URI = "file://gen_firmware.sh "

do_install () {
	install -m 755 ${WORKDIR}/gen_firmware.sh ${STAGING_BINDIR_NATIVE}

}
