DESCRIPTION = "Firmware Image generation"
SECTION = "xoware"
LICENSE = "CLOSED"
#BBCLASSEXTEND = "native"

inherit native
SRCREV = "master"


SRC_URI = "git://github.com/xoware/xomkimage.git;branch=master;protocol=ssh;user=git"
S = "${WORKDIR}/git"



# override S for local dev
#inherit externalsrc
#S = "/home/karl/Work/xoware/xomkimage"

#EXTRA_OEMAKE = "'CC=${CC}' "

do_compile () {
#	cd ${THISDIR}/src
	cd ${S}
	oe_runmake
}


do_install () {
	echo THISDIR = ${THISDIR}
	
	#xomkimage is firmware update to be run from linux UI
	install -m 755 ${S}/xomkimage ${STAGING_BINDIR_NATIVE}
}
