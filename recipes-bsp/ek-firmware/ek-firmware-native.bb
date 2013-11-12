DESCRIPTION = "Firmware Image generation"
SECTION = "bsp"
LICENSE = "CLOSED"


inherit native externalsrc
SRC_URI = "file://gen_firmware.sh "

#S = "${THISDIR}/src"


do_install () {
	echo THISDIR = ${THISDIR}
	
	#gen firmware script is image for programming in uBoot
	install -m 755 ${THISDIR}/files/gen_firmware.sh ${STAGING_BINDIR_NATIVE}
	
}
