##########################################################################
# Enable MVGIU support
##########################################################################
pktio_mvgiu_support=no
AC_ARG_ENABLE([mvgiu_support],
    [  --enable-mvgiu-support  include Marvell (C) GIU support],
    [if test x$enableval = xyes; then
        pktio_mvgiu_support=yes
    fi])

##########################################################################
# Check for MVGIU availability
##########################################################################
if test x$pktio_mvgiu_support = xyes
then
    #AC_CHECK_HEADERS([drivers/mv_giu_gpio.h], [],
    #    [AC_MSG_FAILURE(["can't find MVGIU header"])])
    ODP_CFLAGS="$ODP_CFLAGS -DODP_PKTIO_MVGIU"
else
    pktio_mvgiu_support=no
fi
