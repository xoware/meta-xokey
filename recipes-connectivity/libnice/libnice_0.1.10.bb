SUMMARY = "Interactive Connectivity Establishment library"
DESCRIPTION = "Libnice is an implementation of the IETF's draft Interactive Connectivity Establishment standard (ICE)."
HOMEPAGE = "http://nice.freedesktop.org/wiki/"
SRC_URI = "http://nice.freedesktop.org/releases/libnice-${PV}.tar.gz"

LICENSE = "LGPLv2.1 & MPLv1.1"
LIC_FILES_CHKSUM = "file://COPYING;md5=9c42325015702feda4f4d2f19a55b767 \
                    file://COPYING.LGPL;md5=2d5025d4aa3495befef8f17206a5b0a1 \
                    file://COPYING.MPL;md5=3c617710e51cdbe0fc00716f056dfb1a \
"

PR = "r4"

#DEPENDS = "glib-2.0 gstreamer"
DEPENDS = "glib-2.0"

PACKAGECONFIG ??= ""
PACKAGECONFIG[gupnp] = "--enable-gupnp,--disable-gupnp,gupnp-igd"

#inherit autotools pkgconfig gtk-doc
inherit autotools pkgconfig 

FILES_${PN} += "${libdir}/gstreamer-0.10/*.so"
FILES_${PN}-dev += "${libdir}/gstreamer-0.10/*.la"
FILES_${PN}-staticdev += "${libdir}/gstreamer-0.10/*.a"
FILES_${PN}-dbg += "${libdir}/gstreamer-0.10/.debug"

do_configure_prepend() {
    mkdir ${S}/m4 || true
}

do_compile_append() {
    for i in $(find ${S} -name "*.pc") ; do
        sed -i -e s:${STAGING_DIR_TARGET}::g \
               -e s:/${TARGET_SYS}::g \
                  $i
    done
}

EXTRA_OECONF = " --disable-gupnp --without-gstreamer --disable-gtk-doc "

#for 0.0.13
#SRC_URI[md5sum] = "e5b9f799a57cb939ea2658ec35253ab9"
#SRC_URI[sha256sum] = "d8dd260c486a470a6052a5323920878a084e44a19df09b15728b85c9e3d6edf0"

SRC_URI[md5sum] = "27b62d0093ce29a39df1c6fcf0bb4396"
SRC_URI[sha256sum] = "1dbfb663b730889ae8cab13a2913fe557d581f70b513c918bbbd0b7d3eefebc9"

