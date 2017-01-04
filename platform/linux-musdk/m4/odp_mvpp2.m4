##########################################################################
# Enable MVPP2 support
##########################################################################
pktio_mvpp2_support=no
AC_ARG_ENABLE([mvpp2_support],
    [  --enable-mvpp2-support  include Marvell (C) PP2 IO support],
    [if test x$enableval = xyes; then
        pktio_mvpp2_support=yes
    fi])

##########################################################################
# Check for MVPP2 availability
##########################################################################
if test x$pktio_mvpp2_support = xyes
then
    #AC_CHECK_HEADERS([drivers/mv_pp2.h], [],
    #    [AC_MSG_FAILURE(["can't find MVPP2 header"])])
    ODP_CFLAGS="$ODP_CFLAGS -DODP_PKTIO_MVPP2"
else
    pktio_mvpp2_support=no
fi

##########################################################################
# Restore old saved variables
##########################################################################
CPPFLAGS=$OLD_CPPFLAGS
