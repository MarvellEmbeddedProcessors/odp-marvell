# Uncomment this if you need to change the CUSTOM_STR string
#export CUSTOM_STR=https://git.linaro.org/lng/odp.git

include $(top_srcdir)/platform/Makefile.inc
include $(top_srcdir)/platform/@with_platform@/Makefile.inc

linux_generic_srcdir = $(top_srcdir)/platform/linux-generic

AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_builddir)/include
AM_CFLAGS +=  -I$(linux_generic_srcdir)/include
# The following lines are temporary W/A until MUSDK will expose its flags
AM_CFLAGS +=	-DMVCONF_TYPES_PUBLIC \
		-DMVCONF_DMA_PHYS_ADDR_T_PUBLIC

include_HEADERS = \
		  $(top_srcdir)/include/odp.h \
		  $(top_srcdir)/include/odp_api.h

odpapiincludedir= $(includedir)/odp/api
odpapiinclude_HEADERS = \
		  $(linux_generic_srcdir)/include/odp/api/align.h \
		  $(linux_generic_srcdir)/include/odp/api/atomic.h \
		  $(linux_generic_srcdir)/include/odp/api/barrier.h \
		  $(linux_generic_srcdir)/include/odp/api/buffer.h \
		  $(linux_generic_srcdir)/include/odp/api/byteorder.h \
		  $(linux_generic_srcdir)/include/odp/api/classification.h \
		  $(linux_generic_srcdir)/include/odp/api/compiler.h \
		  $(linux_generic_srcdir)/include/odp/api/cpu.h \
		  $(linux_generic_srcdir)/include/odp/api/cpumask.h \
		  $(linux_generic_srcdir)/include/odp/api/crypto.h \
		  $(linux_generic_srcdir)/include/odp/api/debug.h \
		  $(linux_generic_srcdir)/include/odp/api/errno.h \
		  $(linux_generic_srcdir)/include/odp/api/event.h \
		  $(linux_generic_srcdir)/include/odp/api/hash.h \
		  $(linux_generic_srcdir)/include/odp/api/hints.h \
		  $(linux_generic_srcdir)/include/odp/api/init.h \
		  $(linux_generic_srcdir)/include/odp/api/packet_flags.h \
		  $(linux_generic_srcdir)/include/odp/api/packet.h \
		  $(linux_generic_srcdir)/include/odp/api/packet_io.h \
		  $(linux_generic_srcdir)/include/odp/api/packet_io_stats.h \
		  $(linux_generic_srcdir)/include/odp/api/pool.h \
		  $(linux_generic_srcdir)/include/odp/api/queue.h \
		  $(linux_generic_srcdir)/include/odp/api/random.h \
		  $(linux_generic_srcdir)/include/odp/api/rwlock.h \
		  $(linux_generic_srcdir)/include/odp/api/rwlock_recursive.h \
		  $(linux_generic_srcdir)/include/odp/api/schedule.h \
		  $(linux_generic_srcdir)/include/odp/api/schedule_types.h \
		  $(linux_generic_srcdir)/include/odp/api/shared_memory.h \
		  $(linux_generic_srcdir)/include/odp/api/spinlock.h \
		  $(linux_generic_srcdir)/include/odp/api/spinlock_recursive.h \
		  $(linux_generic_srcdir)/include/odp/api/std_clib.h \
		  $(linux_generic_srcdir)/include/odp/api/std_types.h \
		  $(linux_generic_srcdir)/include/odp/api/sync.h \
		  $(linux_generic_srcdir)/include/odp/api/system_info.h \
		  $(linux_generic_srcdir)/include/odp/api/thread.h \
		  $(linux_generic_srcdir)/include/odp/api/thrmask.h \
		  $(linux_generic_srcdir)/include/odp/api/ticketlock.h \
		  $(linux_generic_srcdir)/include/odp/api/time.h \
		  $(linux_generic_srcdir)/include/odp/api/timer.h \
		  $(linux_generic_srcdir)/include/odp/api/traffic_mngr.h \
		  $(linux_generic_srcdir)/include/odp/api/version.h \
		  $(linux_generic_srcdir)/include/odp/api/visibility_begin.h \
		  $(linux_generic_srcdir)/include/odp/api/visibility_end.h \
		  $(linux_generic_srcdir)/arch/@ARCH_DIR@/odp/api/cpu_arch.h

odpapiplatincludedir= $(includedir)/odp/api/plat
odpapiplatinclude_HEADERS = \
		  $(builddir)/include/odp/api/plat/static_inline.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/atomic_inlines.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/atomic_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/barrier_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/buffer_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/byteorder_inlines.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/byteorder_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/classification_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/cpumask_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/crypto_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/event_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/init_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/packet_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/packet_io_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/pool_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/queue_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/rwlock_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/rwlock_recursive_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/schedule_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/shared_memory_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/spinlock_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/spinlock_recursive_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/std_clib_inlines.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/strong_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/sync_inlines.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/thread_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/thrmask_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/ticketlock_inlines.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/ticketlock_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/time_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/timer_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/traffic_mngr_types.h \
		  $(linux_generic_srcdir)/include/odp/api/plat/version_types.h

noinst_HEADERS = \
		  ${linux_generic_srcdir}/include/odp_align_internal.h \
		  ${linux_generic_srcdir}/include/odp_atomic_internal.h \
		  ${linux_generic_srcdir}/include/odp_buffer_inlines.h \
		  ${linux_generic_srcdir}/include/odp_buffer_internal.h \
		  ${linux_generic_srcdir}/include/odp_classification_datamodel.h \
		  ${linux_generic_srcdir}/include/odp_classification_inlines.h \
		  ${linux_generic_srcdir}/include/odp_classification_internal.h \
		  ${srcdir}/include/odp_config_internal.h \
		  ${linux_generic_srcdir}/include/odp_crypto_internal.h \
		  ${linux_generic_srcdir}/include/odp_debug_internal.h \
		  ${linux_generic_srcdir}/include/odp_forward_typedefs_internal.h \
		  ${linux_generic_srcdir}/include/odp_internal.h \
		  ${linux_generic_srcdir}/include/odp_name_table_internal.h \
		  ${linux_generic_srcdir}/include/odp_packet_internal.h \
		  ${srcdir}/include/odp_packet_io_internal.h \
		  ${linux_generic_srcdir}/include/odp_packet_io_ipc_internal.h \
		  ${linux_generic_srcdir}/include/odp_packet_io_queue.h \
		  ${linux_generic_srcdir}/include/odp_packet_io_ring_internal.h \
		  ${linux_generic_srcdir}/include/odp_packet_netmap.h \
		  ${linux_generic_srcdir}/include/odp_packet_dpdk.h \
		  ${linux_generic_srcdir}/include/odp_packet_socket.h \
		  ${linux_generic_srcdir}/include/odp_packet_tap.h \
		  ${linux_generic_srcdir}/include/odp_pkt_queue_internal.h \
		  ${linux_generic_srcdir}/include/odp_pool_internal.h \
		  ${srcdir}/include/odp_packet_musdk.h \
		  ${linux_generic_srcdir}/include/odp_posix_extensions.h \
		  ${linux_generic_srcdir}/include/odp_queue_internal.h \
		  ${linux_generic_srcdir}/include/odp_schedule_if.h \
		  ${linux_generic_srcdir}/include/odp_schedule_internal.h \
		  ${linux_generic_srcdir}/include/odp_schedule_ordered_internal.h \
		  ${linux_generic_srcdir}/include/odp_sorted_list_internal.h \
		  ${linux_generic_srcdir}/include/odp_shm_internal.h \
		  ${linux_generic_srcdir}/include/odp_timer_internal.h \
		  ${linux_generic_srcdir}/include/odp_timer_wheel_internal.h \
		  ${linux_generic_srcdir}/include/odp_traffic_mngr_internal.h \
		  ${linux_generic_srcdir}/include/protocols/eth.h \
		  ${linux_generic_srcdir}/include/protocols/ip.h \
		  ${linux_generic_srcdir}/include/protocols/ipsec.h \
		  ${linux_generic_srcdir}/include/protocols/tcp.h \
		  ${linux_generic_srcdir}/include/protocols/udp.h \
		  ${linux_generic_srcdir}/Makefile.inc

__LIB__libodp_linux_la_SOURCES = \
			   ../linux-generic/odp_atomic.c \
			   ../linux-generic/odp_barrier.c \
			   ../linux-generic/odp_buffer.c \
			   ../linux-generic/odp_byteorder.c \
			   ../linux-generic/odp_classification.c \
			   ../linux-generic/odp_cpu.c \
			   ../linux-generic/odp_cpumask.c \
			   ../linux-generic/odp_cpumask_task.c \
			   odp_crypto.c \
			   ../linux-generic/odp_errno.c \
			   ../linux-generic/odp_event.c \
			   ../linux-generic/odp_hash.c \
			   ../linux-generic/odp_init.c \
			   ../linux-generic/odp_impl.c \
			   ../linux-generic/odp_name_table.c \
			   ../linux-generic/odp_packet.c \
			   ../linux-generic/odp_packet_flags.c \
			   ../linux-generic/odp_packet_io.c \
			   ../linux-generic/pktio/ethtool.c \
			   pktio/io_ops.c \
			   ../linux-generic/pktio/ipc.c \
			   ../linux-generic/pktio/pktio_common.c \
			   ../linux-generic/pktio/loop.c \
			   ../linux-generic/pktio/netmap.c \
			   ../linux-generic/pktio/dpdk.c \
			   ../linux-generic/pktio/socket.c \
			   ../linux-generic/pktio/socket_mmap.c \
			   ../linux-generic/pktio/sysfs.c \
			   ../linux-generic/pktio/tap.c \
			   ../linux-generic/pktio/ring.c \
			   ../linux-generic/odp_pkt_queue.c \
			   ../linux-generic/odp_pool.c \
			   ../linux-generic/odp_queue.c \
			   ../linux-generic/odp_rwlock.c \
			   ../linux-generic/odp_rwlock_recursive.c \
			   ../linux-generic/odp_schedule.c \
			   ../linux-generic/odp_schedule_if.c \
			   ../linux-generic/odp_schedule_ordered.c \
			   ../linux-generic/odp_schedule_sp.c \
			   odp_shared_memory.c \
			   ../linux-generic/odp_sorted_list.c \
			   ../linux-generic/odp_spinlock.c \
			   ../linux-generic/odp_spinlock_recursive.c \
			   ../linux-generic/odp_std_clib.c \
			   ../linux-generic/odp_sync.c \
			   ../linux-generic/odp_system_info.c \
			   ../linux-generic/odp_thread.c \
			   ../linux-generic/odp_thrmask.c \
			   ../linux-generic/odp_ticketlock.c \
			   ../linux-generic/odp_time.c \
			   ../linux-generic/odp_timer.c \
			   ../linux-generic/odp_timer_wheel.c \
			   ../linux-generic/odp_traffic_mngr.c \
			   ../linux-generic/odp_version.c \
			   ../linux-generic/odp_weak.c \
			   ../linux-generic/arch/@ARCH_DIR@/odp_cpu_arch.c \
			   ../linux-generic/arch/@ARCH_DIR@/odp_sysinfo_parse.c

if ODP_PKTIO_MVPP2
__LIB__libodp_linux_la_SOURCES += pktio/mvpp2.c
endif

if HAVE_PCAP
__LIB__libodp_linux_la_SOURCES += ../linux-generic/pktio/pcap.c
endif
