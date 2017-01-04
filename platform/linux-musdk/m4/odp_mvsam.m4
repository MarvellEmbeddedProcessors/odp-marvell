##########################################################################
# Enable MVSAM support
##########################################################################
pktio_mvsam_support=no
AC_ARG_ENABLE([mvsam_support],
    [  --enable-mvsam-support  include Marvell (C) SAM IO support],
    [if test x$enableval = xyes; then
        pktio_mvsam_support=yes
    fi])

##########################################################################
# Check for MVSAM availability
##########################################################################
if test x$pktio_mvsam_support = xyes
then
    #AC_CHECK_HEADERS([drivers/mv_sam.h], [],
    #    [AC_MSG_FAILURE(["can't find MVSAM header"])])
    ODP_CFLAGS="$ODP_CFLAGS -DODP_PKTIO_MVSAM"
else
    pktio_mvsam_support=no
fi

##########################################################################
# Restore old saved variables
##########################################################################
CPPFLAGS=$OLD_CPPFLAGS
