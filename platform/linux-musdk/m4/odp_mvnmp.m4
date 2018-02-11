##########################################################################
# Enable MVNMP-Guest mode
##########################################################################
mvnmp_guest_mode=no
AC_ARG_ENABLE([mvnmp_guest_mode],
    [  --enable-mvnmp-guest-mode  include Marvell (C) NMP Guest mode],
    [if test x$enableval = xyes; then
		mvnmp_guest_mode=yes
    fi])

##########################################################################
# Check for MVNMP availability
##########################################################################
if test x$mvnmp_guest_mode = xyes
then
    ODP_CFLAGS="$ODP_CFLAGS -DODP_MVNMP_GUEST_MODE"
else
    mvnmp_guest_mode=no
fi
##########################################################################
# Restore old saved variables
##########################################################################
CPPFLAGS=$OLD_CPPFLAGS
