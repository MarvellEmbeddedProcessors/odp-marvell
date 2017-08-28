##########################################################################
# Enable MVNMP support
##########################################################################
mvnmp_support=no
AC_ARG_ENABLE([mvnmp_support],
    [  --enable-mvnmp-support  include Marvell (C) NMP support],
    [if test x$enableval = xyes; then
        mvnmp_support=yes
    fi])

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
if test x$mvnmp_support = xyes
then
    #AC_CHECK_HEADERS([mng/mv_nmp.h], [],
    #    [AC_MSG_FAILURE(["can't find MVNMP header"])])
    ODP_CFLAGS="$ODP_CFLAGS -DODP_MVNMP"
else
    mvnmp_support=no
fi

if test x$mvnmp_guest_mode = xyes
then
    if test x$mvnmp_support = xno
	then
            echo "enable_mvnmp_support must be set"
            exit 1
	fi
    ODP_CFLAGS="$ODP_CFLAGS -DODP_MVNMP_GUEST_MODE"
else
    mvnmp_guest_mode=no
fi
##########################################################################
# Restore old saved variables
##########################################################################
CPPFLAGS=$OLD_CPPFLAGS
