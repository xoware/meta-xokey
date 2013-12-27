# look for files in the layer first
FILESEXTRAPATHS_prepend := "${THISDIR}/${PN}:"

SRC_URI += "file://linux_openssl_cryptodev_1.6.patch file://cryptodev_h_1.6.patch file://test_evp.patch"
#SRC_URI += "file://cryptodev_h_1.6.patch file://test_evp.patch"

#remove ocf-linux
DEPENDS = ""

#CFLAG=`echo ${CFLAG} | sed -e 's/-DUSE_CRYPTODEV_DIGESTS//g'`
CFLAG = "${@base_conditional('SITEINFO_ENDIANNESS', 'le', '-DL_ENDIAN', '-DB_ENDIAN', d)} \
        -DTERMIO ${CFLAGS} -Wall -Wa,--noexecstack -DHAVE_CRYPTODEV "

#-DUSE_CRYPTODEV_DIGESTS


do_compile_append () {
	oe_runmake build_tests V=1
	cd test
	oe_runmake
}