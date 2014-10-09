DESCRIPTION = "Firmware Image generation"
SECTION = "xoware"
LICENSE = "CLOSED"
#BBCLASSEXTEND = "native"

inherit native
SRCREV = "master"


SRC_URI = "git://github.com/xoware/xomkimage.git;branch=master;protocol=ssh;user=git"
S = "${WORKDIR}/git"


SRC_URI +=  "file://mkimage-key.sexp"
SRC_URI +=  "file://rootfs-key.sexp"
SRC_URI +=  "file://sign_kernel_config_fit.its"
SRC_URI +=  "file://kernel_key.key"
SRC_URI +=  "file://kernel_key.crt"

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
	install -m 755 ${S}/xomkimage_v1 ${STAGING_BINDIR_NATIVE}
	install -m 755 ${S}/xosignappend ${STAGING_BINDIR_NATIVE}
	mkdir -p ${DEPLOY_DIR_IMAGE}
	install -m 755 ${WORKDIR}/sign_kernel_config_fit.its ${DEPLOY_DIR_IMAGE}
	install -m 755 ${WORKDIR}/sign_kernel_config_fit.its ${STAGING_BINDIR_NATIVE}

	#keep these keys safe
	install -m 400 ${WORKDIR}/mkimage-key.sexp ${STAGING_BINDIR_NATIVE}
	install -m 400 ${WORKDIR}/rootfs-key.sexp ${STAGING_BINDIR_NATIVE}
	
	install -d ${STAGING_ETCDIR_NATIVE}
	install -d ${STAGING_ETCDIR_NATIVE}/keys
	install -m 400 ${WORKDIR}/kernel_key.key ${STAGING_ETCDIR_NATIVE}/keys
	install -m 400 ${WORKDIR}/kernel_key.crt ${STAGING_ETCDIR_NATIVE}/keys
}
