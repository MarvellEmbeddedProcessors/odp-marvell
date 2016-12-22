include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_bridge$(EXEEXT)
odp_bridge_LDFLAGS = $(AM_LDFLAGS) -static
odp_bridge_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example -Wno-unused-but-set-variable -Wno-unused-function -Wno-unused-variable -Wno-maybe-uninitialized -Wno-unused-parameter

noinst_HEADERS = $(top_srcdir)/example/example_debug.h

dist_odp_bridge_SOURCES = odp_bridge.c
