/* Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp_packet_io_internal.h>
#include <odp_packet_musdk.h>
#include <odp_debug_internal.h>

/* MUSDK GIU public interfaces */
#include <drivers/mv_giu_gpio.h>
#include <drivers/mv_giu_bpool.h>

/* prefetch=2, tested to be optimal both for
   mvgiu_recv() & mvgiu_send() prefetch operations */
#define MVGIU_PREFETCH_SHIFT		2
#define BUFFER_RELEASE_BURST_SIZE	64

static int mvgiu_init_global(void)
{
	return 0;
}

static int mvgiu_term_global(void)
{
	return 0;
}

static int mvgiu_init_local(void)
{
	return 0;
}

/**
 * Initialize capability values
 *
 * @param pktio_entry    Packet IO entry
 */
static void init_capability(pktio_entry_t *pktio_entry)
{
	odp_pktio_capability_t *capa = &pktio_entry->s.pkt_mvgiu.capa;

	memset(capa, 0, sizeof(odp_pktio_capability_t));
}

static int mvgiu_open(odp_pktio_t pktio ODP_UNUSED,
		      pktio_entry_t *pktio_entry ODP_UNUSED,
		      const char *devname ODP_UNUSED,
		      odp_pool_t pool ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static int mvgiu_close(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static int mvgiu_start(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static int mvgiu_stop(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static int mvgiu_capability(pktio_entry_t *pktio_entry ODP_UNUSED,
			    odp_pktio_capability_t *capa ODP_UNUSED)
{
	*capa = pktio_entry->s.pkt_mvgiu.capa;
	return 0;
}

static int mvgiu_stats(pktio_entry_t *pktio_entry ODP_UNUSED,
		       odp_pktio_stats_t *stats ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static int mvgiu_stats_reset(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static uint32_t mvgiu_mtu_get(pktio_entry_t *pktio_entry)
{
	return pktio_entry->s.pkt_mvgiu.mtu;
}

static int mvgiu_mac_get(pktio_entry_t *pktio_entry ODP_UNUSED,
			 void *mac_addr ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static int mvgiu_promisc_mode_get(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	/* Promiscuous is always enable */
	return 1;
}

static int mvgiu_link_status(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	/* Link is always up */
	return 1;
}

static int mvgiu_recv(pktio_entry_t *pktio_entry ODP_UNUSED,
		      int rxq_id ODP_UNUSED,
		      odp_packet_t pkt_table[] ODP_UNUSED,
		      int num_pkts ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

/* An implementation for enqueuing packets */
static int mvgiu_send(pktio_entry_t *pktio_entry ODP_UNUSED,
		      int txq_id ODP_UNUSED,
		      const odp_packet_t pkt_table[] ODP_UNUSED,
		      int num_pkts ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

const pktio_if_ops_t mvgiu_pktio_ops = {
	.name = "odp-mvgiu",
	.print = NULL,
	.init_global = mvgiu_init_global,
	.init_local = mvgiu_init_local,
	.term = mvgiu_term_global,
	.open = mvgiu_open,
	.close = mvgiu_close,
	.start = mvgiu_start,
	.stop = mvgiu_stop,
	.capability = mvgiu_capability,
	.config = NULL,
	.input_queues_config = NULL,
	.output_queues_config = NULL,
	.stats = mvgiu_stats,
	.stats_reset = mvgiu_stats_reset,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.mtu_get = mvgiu_mtu_get,
	.promisc_mode_set = NULL,
	.promisc_mode_get = mvgiu_promisc_mode_get,
	.mac_get = mvgiu_mac_get,
	.link_status = mvgiu_link_status,
	.recv = mvgiu_recv,
	.send = mvgiu_send,
};
