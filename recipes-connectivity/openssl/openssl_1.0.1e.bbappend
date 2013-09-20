# look for files in the layer first
FILESEXTRAPATHS_prepend := "${THISDIR}/${PN}:"

SRC_URI += "file://linux_openssl_cryptodev_1.5.patch file://cryptodev_h.patch"

#remove ocf-linux
DEPENDS = ""
