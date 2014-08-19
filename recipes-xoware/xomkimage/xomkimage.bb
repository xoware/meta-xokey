DESCRIPTION = "Firmware Image generation"
SECTION = "xoware"
LICENSE = "CLOSED"
#BBCLASSEXTEND = "native"

SRCREV = "master"


SRC_URI = "git://github.com/xoware/xomkimage.git;branch=master;protocol=ssh;user=git"
S = "${WORKDIR}/git"

# Do NOT put private KEYS in the image!
#SRC_URI +=  "file://mkimage-key.sexp"
#SRC_URI +=  "file://rootfs-key.sexp"

# override S for local dev
# inherit externalsrc
# S = "/home/karl/Work/xoware/xomkimage"

#EXTRA_OEMAKE = "'CC=${CC}' "

do_compile () {
#	cd ${THISDIR}/src
	cd ${S}
	oe_runmake
}


do_install () {
	echo THISDIR = ${THISDIR}
	
	install -d ${D}/usr
	install -d ${D}/usr/bin
	install -m 755 ${S}/xosigcheck ${D}/usr/bin
	
}
