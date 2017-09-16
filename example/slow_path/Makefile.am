include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_slow_path$(EXEEXT)
odp_slow_path_LDFLAGS = $(AM_LDFLAGS) -static
odp_slow_path_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

dist_odp_slow_path_SOURCES = odp_slow_path.c

if test_example
TESTS = odp_slow_path
endif
