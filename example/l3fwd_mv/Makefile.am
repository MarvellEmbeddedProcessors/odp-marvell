include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_l3fwd_mv$(EXEEXT)
odp_l3fwd_mv_LDFLAGS = $(AM_LDFLAGS) -static
odp_l3fwd_mv_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example -I${top_srcdir}/test -D_DEFAULT_SOURCE

noinst_HEADERS = \
		  $(top_srcdir)/example/l3fwd_mv/odp_l3fwd_db_mv.h \
		  $(top_srcdir)/example/l3fwd_mv/odp_l3fwd_lpm_mv.h \
		  $(top_srcdir)/example/example_debug.h \
		  $(top_srcdir)/example/l3fwd_mv/xxhash.h \
		  $(top_srcdir)/example/l3fwd_mv/ezxml.h

dist_odp_l3fwd_mv_SOURCES = odp_l3fwd_mv.c odp_l3fwd_db_mv.c odp_l3fwd_lpm_mv.c xxhash.c ezxml.c

if test_example
if HAVE_PCAP
TESTS = odp_l3fwd_run_mv.sh
endif
endif

EXTRA_DIST = odp_l3fwd_run_mv.sh udp64.pcap
