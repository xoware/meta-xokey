DESCRIPTION = "Jansson is a C library for encoding, decoding and manipulating JSON data."
HOMEPAGE = "http://www.digip.org/jansson/"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=74ead53343bf648f8f588341b2f8fa16"

SRC_URI = "http://www.digip.org/jansson/releases/${BPN}-${PV}.tar.gz"

SRC_URI[md5sum] = "00dd7b55c01c74cac59df398208b92ed"
SRC_URI[sha256sum] = "98fa4dd0e0dff679e5085490f5fafa38bdda088f4553348c0281832d24afe541"

inherit autotools pkgconfig

