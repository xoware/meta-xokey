# look for files in the layer first
FILESEXTRAPATHS_prepend := "${THISDIR}/${PN}:"

SRC_URI += "file://linux_openssl_cryptodev_1.6.patch file://cryptodev_h_1.6.patch file://test_evp.patch"

#remove ocf-linux
DEPENDS = ""


do_compile_append () {
	oe_runmake build_tests V=1
	cd test
	oe_runmake
}