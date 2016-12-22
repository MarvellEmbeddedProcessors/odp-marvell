include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_nat$(EXEEXT)
odp_nat_LDFLAGS = $(AM_LDFLAGS) -static
odp_nat_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example -Wno-unused-but-set-variable -Wno-unused-function -Wno-unused-variable -Wno-maybe-uninitialized -Wno-unused-parameter

noinst_HEADERS = \
	$(top_srcdir)/example/nat/xxhash.h \
	$(top_srcdir)/example/example_debug.h

dist_odp_nat_SOURCES = xxhash.c odp_nat.c
