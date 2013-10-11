
# As of Oct 2013 their master branch has 3.6 fixes that are not in other branches
KBRANCH = "master"

#add recipie that has our initramfs
INITRAMFS_IMAGE = "exokey-initramfs"


# path to get defconfig from
FILESEXTRAPATHS_prepend := "${THISDIR}/linux-3.6" 


SRCREV="e5fb8621b409acf95c64d543102e2c89aa006b42"
PV = "${LINUX_VERSION}+${SRCREV}"


#add exokey machine
COMPATIBLE_MACHINE = "(sama5d3xek|at91sam9x5ek|exokey)"