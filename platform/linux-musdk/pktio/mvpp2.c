/* Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#ifdef ODP_PKTIO_MVPP2

#include <odp_posix_extensions.h>

#include <odp_packet_io_internal.h>
#include <odp_packet_musdk.h>
#include <odp_packet_socket.h>
#include <odp_debug_internal.h>
#include <protocols/eth.h>

#include <odp/api/ticketlock.h>
#include <odp_pool_internal.h>
#include <odp_packet_io_ring_internal.h>
#include <odp_classification_inlines.h>
#include <odp_classification_internal.h>

/* MUSDK PP2 public interfaces */
#include <drivers/mv_pp2.h>
#include <drivers/mv_pp2_hif.h>
#include <drivers/mv_pp2_bpool.h>
#include <drivers/mv_pp2_ppio.h>


#define USE_LPBK_SW_RECYLCE


/*#define USE_HW_BUFF_RECYLCE*/
#define MAX_NUM_QS_PER_CORE		MVPP2_MAX_NUM_TCS_PER_PORT
#define MAX_NUM_PACKPROCS		1

#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((u32)(n))

/* Macro for checking if a number is a power of 2 */
#define POWER_OF_2(_n)	(!((_n) & ((_n) - 1)))
#define NEXT_POWER_OF_2(_num, _new_num) \
do {					\
	if (POWER_OF_2(_num))		\
		_new_num = (_num);	\
	else {				\
		uint64_t tmp = (_num);	\
		_new_num = 1;		\
		while (tmp) {		\
			_new_num <<= 1;	\
			tmp >>= 1;	\
		}			\
	}				\
} while (0)

typedef struct port_desc {
	const char	*name;
	int		 pp_id;
	int		 ppio_id;
} port_desc_t;

struct tx_shadow_q {
	u16				 read_ind;
	u16				 write_ind;

	struct pp2_buff_inf		 buffs_inf[MVPP2_Q_SIZE];
};

/* Per thread unique ID used during run-time BM and HIF
 * resource indexing
 */
struct thd_info {
	int			 id;
	struct pp2_hif		*hif;
	struct tx_shadow_q	 shadow_qs[MAX_NUM_QS_PER_CORE];
};

/* Per input-Q used during run-time */
struct inq_info {
	u8			 first_tc;
	u8			 num_tcs;
	u8			 first_qid;
	u8			 num_qids;
	int			 lockless;
	odp_ticketlock_t	 lock;  /**< Queue lock */
};

static uint32_t		 used_bpools = MVPP2_BPOOL_RSRV;
static uint64_t		 sys_dma_high_addr = (~0LL);

/* Global lock used for control containers and other accesses */
static odp_ticketlock_t thrs_lock;
/* Per thread unique ID used during run-time BM and HIF
 * resource indexing
 */
static __thread int pp2_thr_id;
static struct thd_info		 thds[MVPP2_TOTAL_NUM_HIFS] = {};
static struct inq_info		 inqs[MVPP2_MAX_NUM_QS_PER_TC] = {};

/* Get HIF object ID for this thread */
static inline int get_thr_id(void)
{
	return pp2_thr_id;
}

/* Reserve HIF or BM object ID for this thread */
static inline int thread_rsv_id(void)
{
	pp2_thr_id = odp_thread_id();
	return 0;
}

static int find_port_info(port_desc_t *port_desc)
{
	char		 name[20];
	u8		 pp, ppio;
	int		 err;

	if (!port_desc->name) {
		ODP_ERR("No port name given!\n");
		return -1;
	}

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s", port_desc->name);
	if ((err = pp2_netdev_get_ppio_info(name,
					    &pp,
					    &ppio)) != 0) {
		ODP_ERR("PP2 Port %s not found!\n", port_desc->name);
		return err;
	}

	port_desc->ppio_id = ppio;
	port_desc->pp_id = pp;

	return 0;
}

static int find_free_bpool(void)
{
	int	i;

	odp_ticketlock_lock(&thrs_lock);
	for (i = 0; i < MVPP2_TOTAL_NUM_BPOOLS; i++) {
		if (!((uint64_t)(1 << i) & used_bpools)) {
			used_bpools |= (uint64_t)(1 << i);
			break;
		}
	}
	odp_ticketlock_unlock(&thrs_lock);
	if (i == MVPP2_TOTAL_NUM_BPOOLS)
		return -1;
	return i;
}

static int fill_bpool(odp_pool_t	 pool,
		      struct pp2_bpool	*bpool,
		      struct pp2_hif	*hif,
		      int		 num,
		      int		 alloc_len)
{
	int			 i, err = 0;
#ifndef USE_LPBK_SW_RECYLCE
	odp_packet_t		 pkt;
	static int		 first = 1;
	struct pp2_buff_inf	 buff_inf;
#else
	odp_packet_t		 *pkt;
	struct buff_release_entry buff_array[MVPP2_Q_SIZE];
	int j = 0, err2 = 0;
	u16 final_num, num_bufs;
#endif


#ifndef USE_LPBK_SW_RECYLCE
	for (i = 0; i < num; i++) {
		if (packet_alloc_multi(pool, alloc_len, &pkt, 1) != 1)
			return -1;
		if (!pkt || (pkt == ODP_PACKET_INVALID)) {
			ODP_ERR("Allocated invalid pkt; skipping!\n");
			continue;
		}

		if (first) {
			odp_ticketlock_lock(&thrs_lock);
			if (sys_dma_high_addr == (uint64_t)(~0LL)) {
				sys_dma_high_addr = ((u64)pkt) & (~((1ULL << 32) - 1));
				ODP_DBG("sys_dma_high_addr (0x%lx)\n", sys_dma_high_addr);
			}
			first = 0;
			odp_ticketlock_unlock(&thrs_lock);
		}
		if ((upper_32_bits((u64)pkt)) != (sys_dma_high_addr >> 32)) {
			ODP_ERR("pkt(%p)  upper out of range; skipping\n", pkt);
			continue;
		}

		if (!odp_packet_head(pkt)) {
			ODP_ERR("Allocated invalid pkt (no buffer)!\n");
			continue;
		}

		buff_inf.cookie =
			lower_32_bits((u64)(uintptr_t)pkt); /* cookie contains lower_32_bits of the va */
		buff_inf.addr   =
			(bpool_dma_addr_t)mv_sys_dma_mem_virt2phys(odp_packet_head(pkt));
		err = pp2_bpool_put_buff(hif, bpool, &buff_inf);
		if (err != 0)
			return err;
	}
#else
	pkt = malloc(num * sizeof(odp_packet_t));

	if ((final_num = packet_alloc_multi(pool, alloc_len, pkt, num)) != num)
		err = -1;
	i = 0;
	while((i < final_num) && (!pkt[i] || pkt[i] == ODP_PACKET_INVALID)) {
		ODP_ERR("Allocated invalid pkt, pkt_num %d out of %d; skipping!\n", i, final_num);
		i++;
	}
	if (unlikely(i == final_num)) {
		err = -1;
		goto err;
	}

	odp_ticketlock_lock(&thrs_lock);
	if (sys_dma_high_addr == (uint64_t)(~0LL)) {
		sys_dma_high_addr = ((u64)pkt[i]) & (~((1ULL << 32) - 1));
		ODP_DBG("sys_dma_high_addr (0x%lx)\n", sys_dma_high_addr);
	}
	odp_ticketlock_unlock(&thrs_lock);

	for (; i < final_num; i++) {
		if (!pkt[i] || (pkt[i] == ODP_PACKET_INVALID)) {
			ODP_ERR("Allocated invalid pkt; skipping!\n");
			continue;
		}

		if ((upper_32_bits((u64)pkt[i])) != (sys_dma_high_addr >> 32)) {
			ODP_ERR("pkt(%p)  upper out of range; skipping\n", pkt[i]);
			continue;
		}

		if (!odp_packet_head(pkt[i])) {
			ODP_ERR("Allocated invalid pkt (no buffer)!\n");
			continue;
		}
		buff_array[j].bpool = bpool;
		buff_array[j].buff.cookie =
			lower_32_bits((u64)(uintptr_t)pkt[i]); /* cookie contains lower_32_bits of the va */
		buff_array[j].buff.addr =
			(bpool_dma_addr_t)mv_sys_dma_mem_virt2phys(odp_packet_head(pkt[i]));
		j++;
	}
	num_bufs = j;
	err2 = pp2_bpool_put_buffs(hif, buff_array, &num_bufs);
err:
	free(pkt);
	if (err2)
		return(err2);
	return(err);

#endif

	return 0;
}

static int mvpp2_init_global(void)
{
	struct pp2_init_params	pp2_params;
	int			err;

	/* Master thread. Init locks */
	odp_ticketlock_init(&thrs_lock);

	memset(&pp2_params, 0, sizeof(pp2_params));
	/* TODO: the following lines should be dynamic! */
	pp2_params.hif_reserved_map = MVPP2_HIF_RSRV;
	pp2_params.bm_pool_reserved_map = MVPP2_BPOOL_RSRV;

	err = pp2_init(&pp2_params);
	if (err != 0) {
		ODP_ERR("PP2 init failed (%d)!\n", err);
		return -1;
	}

	return 0;
}

static int mvpp2_term_global(void)
{
	pp2_deinit();
	return 0;
}

static int mvpp2_init_local(void)
{
	struct pp2_hif_params		hif_params;
	char				name[15];
	int				offs, id, err;

	/* Egress worker thread. Provide an unique ID for resource use */
	thread_rsv_id();

	id = get_thr_id();

	for (offs = 0; offs < MVPP2_TOTAL_NUM_HIFS; offs++)
		if (!((1 << offs) & MVPP2_HIF_RSRV))
			break;
	if (offs == MVPP2_TOTAL_NUM_HIFS) {
		ODP_ERR("No available HIFs for this thread!!!\n");
		return -1;
	}

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "hif-%d", id + offs);
	memset(&hif_params, 0, sizeof(hif_params));
	hif_params.match = name;
	hif_params.out_size = MVPP2_Q_SIZE;
	err = pp2_hif_init(&hif_params, &thds[id].hif);
	if (err != 0)
		return err;
	if (!thds[id].hif) {
		ODP_ERR("HIF init failed!\n");
		return -EIO;
	}

	return 0;
}

/**
 * Initialize capability values
 *
 * @param pktio_entry    Packet IO entry
 */
static void init_capability(pktio_entry_t *pktio_entry)
{
	odp_pktio_capability_t *capa = &pktio_entry->s.pkt_mvpp2.capa;

	memset(capa, 0, sizeof(odp_pktio_capability_t));

	/* TODO: support only RSS now (no support for QoS!) */
	capa->max_input_queues = (MVPP2_MAX_NUM_TCS_PER_PORT * MVPP2_MAX_NUM_QS_PER_TC);
	capa->max_output_queues = (MVPP2_MAX_NUM_TCS_PER_PORT * MVPP2_MAX_NUM_QS_PER_TC);
	capa->loop_supported = true;
	odp_pktio_config_init(&capa->config);
}

static int mvpp2_open(odp_pktio_t pktio ODP_UNUSED,
		      pktio_entry_t *pktio_entry,
		      const char *devname,
		      odp_pool_t pool)
{
	struct pp2_ppio_params		port_params;
	struct pp2_ppio_inq_params	inq_params[MVPP2_MAX_NUM_QS_PER_TC];
	struct pp2_bpool_params		bpool_params;
	port_desc_t			port_desc;
	odp_pktin_hash_proto_t		hash_proto;
	char				name[15];
	int				i, j, err, pool_id;

	if (strlen(devname) > sizeof(name) - 1) {
		ODP_ERR("Port name (%s) too long!\n", devname);
		return -1;
	}

	memset(&port_desc, 0, sizeof(port_desc));
	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "%s", devname);
	port_desc.name = name;
	err = find_port_info(&port_desc);
	if (err != 0) {
		ODP_ERR("Port info not found!\n");
		return -1;
	}

	/* Allocate a dedicated pool for this port */
	pool_id = find_free_bpool();
	if (pool_id < 0) {
		ODP_ERR("free pool not found!\n");
		return -1;
	}

	pktio_entry->s.pkt_mvpp2.pp_id = port_desc.pp_id;
	pktio_entry->s.pkt_mvpp2.ppio_id = port_desc.ppio_id;
	pktio_entry->s.pkt_mvpp2.mtu = MVPP2_DFLT_MTU;

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "pool-%d:%d", port_desc.pp_id, pool_id);
	memset(&bpool_params, 0, sizeof(bpool_params));
	bpool_params.match = name;
	/* TODO: is this correct? */
	bpool_params.buff_len = pktio_entry->s.pkt_mvpp2.mtu;
	NEXT_POWER_OF_2(bpool_params.buff_len, bpool_params.buff_len);
	err = pp2_bpool_init(&bpool_params, &pktio_entry->s.pkt_mvpp2.bpool);
	if (err != 0) {
		ODP_ERR("BPool init failed!\n");
		return -1;
	}
	if (!pktio_entry->s.pkt_mvpp2.bpool) {
		ODP_ERR("BPool init failed!\n");
		return -1;
	}

	/* Associate this pool with this pktio */
	pktio_entry->s.pkt_mvpp2.pool = pool;
	pktio_entry->s.pkt_mvpp2.bpool_id = pool_id;

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "ppio-%d:%d", port_desc.pp_id, port_desc.ppio_id);
	memset(&port_params, 0, sizeof(port_params));
	port_params.match = name;
	port_params.type = PP2_PPIO_T_NIC;
	port_params.inqs_params.num_tcs = MVPP2_MAX_NUM_TCS_PER_PORT;
	for (i = 0; i < port_params.inqs_params.num_tcs; i++) {
		port_params.inqs_params.tcs_params[i].pkt_offset = MVPP2_PACKET_OFFSET >> 2;
		port_params.inqs_params.tcs_params[i].num_in_qs = MVPP2_MAX_NUM_QS_PER_TC;
		memset(inq_params, 0, sizeof(inq_params));
		for (j = 0; j < port_params.inqs_params.tcs_params[i].num_in_qs; j++)
			inq_params[j].size = MVPP2_Q_SIZE;
		port_params.inqs_params.tcs_params[i].inqs_params = inq_params;
		port_params.inqs_params.tcs_params[i].pools[0] = pktio_entry->s.pkt_mvpp2.bpool;
	}
	port_params.outqs_params.num_outqs = MVPP2_MAX_NUM_TCS_PER_PORT;
	for (i = 0; i < port_params.outqs_params.num_outqs; i++) {
		port_params.outqs_params.outqs_params[i].size = MVPP2_Q_SIZE;
		port_params.outqs_params.outqs_params[i].weight = 1;
	}
	err = pp2_ppio_init(&port_params, &pktio_entry->s.pkt_mvpp2.ppio);
	if (err != 0) {
		ODP_ERR("PP-IO init failed!\n");
		return -1;
	}
	if (!pktio_entry->s.pkt_mvpp2.ppio) {
		ODP_ERR("PP-IO init failed!\n");
		return -1;
	}

	pool_entry_t *poole = get_pool_entry(pool_handle_to_index(pool));
	/* Allocate maximum sized packets */
	/* Allocate half of the SW pool into the HW pool; i.e. allow only 2 ports sharing the same SW pool */
	err = fill_bpool(pktio_entry->s.pkt_mvpp2.pool, pktio_entry->s.pkt_mvpp2.bpool, thds[get_thr_id()].hif,
			 poole->s.buf_num / 2, pktio_entry->s.pkt_mvpp2.mtu);
	if (err != 0) {
		ODP_ERR("can't fill port pool with buffs!\n");
		return -1;
	}

	init_capability(pktio_entry);

	pktio_entry->s.pkt_mvpp2.sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (pktio_entry->s.pkt_mvpp2.sockfd == -1) {
		ODP_ERR("Cannot get device control socket\n");
		return -1;
	}

	/* TODO: temporary until we have appropriate implementation for RSS */
	/* Check if RSS is supported. If not, set 'max_input_queues' to 1. */
	if (rss_conf_get_supported_fd(pktio_entry->s.pkt_mvpp2.sockfd, devname, &hash_proto) == 0) {
		ODP_PRINT("RSS not supported\n");
		pktio_entry->s.pkt_mvpp2.capa.max_input_queues = 1;
	}

	/* TODO: temporary until we have ppio_get_mac_addr() */
	err = mac_addr_get_fd(pktio_entry->s.pkt_mvpp2.sockfd, devname, pktio_entry->s.pkt_mvpp2.if_mac);
	if (err != 0) {
		ODP_ERR("Cannot get device MAC address (%d)!\n", err);
		return -1;
	}

	ODP_DBG("port '%s' is opened\n", devname);

	/* Set default num queues - will be updated at config */
	pktio_entry->s.num_in_queue = 0;
	pktio_entry->s.num_out_queue = 0;

	return 0;
}

static int mvpp2_close(pktio_entry_t *pktio_entry)
{
	/* Close (destroy) the PP2 port */
pr_line;
	pp2_ppio_deinit(pktio_entry->s.pkt_mvpp2.ppio);
	ODP_DBG("port '%s' was closed\n", pktio_entry->s.name);
pr_line;
	return 0;
}

static int mvpp2_start(pktio_entry_t *pktio_entry)
{
	if (!pktio_entry->s.num_in_queue && !pktio_entry->s.num_out_queue) {
		ODP_ERR("No input and output queues configured!\n");
		return -1;
	}

	pp2_ppio_enable(pktio_entry->s.pkt_mvpp2.ppio);

	ODP_PRINT("PktIO PP2 has %d RxTCs with %d RxQs each and %d TxTCs\n",
		  MVPP2_MAX_NUM_TCS_PER_PORT,
		  MVPP2_MAX_NUM_QS_PER_TC,
		  MVPP2_MAX_NUM_TCS_PER_PORT);
	ODP_PRINT("\t mapped to %d RxQs and %d TxQs!!!\n",
		  pktio_entry->s.num_in_queue, pktio_entry->s.num_out_queue);

	ODP_DBG("port '%s' is ready\n", pktio_entry->s.name);
	return 0;
}

static int mvpp2_stop(pktio_entry_t *pktio_entry)
{
	/* Set the PP2 port in standby-mode.
	 * Ingress and egress disabled
	 */
pr_line;
	pp2_ppio_disable(pktio_entry->s.pkt_mvpp2.ppio);
	ODP_DBG("port '%s' was stopped\n", pktio_entry->s.name);
pr_line;
	return 0;
}

static int mvpp2_capability(pktio_entry_t *pktio_entry,
			    odp_pktio_capability_t *capa)
{
	*capa = pktio_entry->s.pkt_mvpp2.capa;
	return 0;
}

static int mvpp2_input_queues_config(pktio_entry_t *pktio_entry,
				     const odp_pktin_queue_param_t *param)
{
	u32	 max_num_hwrx_qs;
	int		 i, max_num_hwrx_qs_per_inq;
	u32	 num_rxq = param->num_queues;

	ODP_ASSERT(num_rxq == pktio_entry->s.num_in_queue);

	/* TODO: only support now RSS; no support for QoS; how to translate rxq_id to tc/qid???? */
	if (num_rxq > MVPP2_MAX_NUM_QS_PER_TC) {
		ODP_ERR("Too many input Queues configured for port (%d vs %d)\n",
			num_rxq, MVPP2_MAX_NUM_QS_PER_TC);
		return -1;
	}

	max_num_hwrx_qs = (MVPP2_MAX_NUM_TCS_PER_PORT * MVPP2_MAX_NUM_QS_PER_TC);
	if (pktio_entry->s.num_in_queue > max_num_hwrx_qs) {
		ODP_ERR("Too many In-Queues mapped (%d vs %d)!\n",
			pktio_entry->s.num_in_queue,
			max_num_hwrx_qs);
		return -1;
	}
	if (max_num_hwrx_qs % pktio_entry->s.num_in_queue) {
		ODP_ERR("Invalid Queue mapping (%d vs %d)!\n",
			pktio_entry->s.num_in_queue,
			max_num_hwrx_qs);
		return -1;
	}

	max_num_hwrx_qs_per_inq = max_num_hwrx_qs / pktio_entry->s.num_in_queue;
	for (i = 0; i < MVPP2_MAX_NUM_QS_PER_TC; i++) {
		inqs[i].first_tc = 0;
		inqs[i].num_tcs = 1;
		inqs[i].first_qid = (i * max_num_hwrx_qs_per_inq);
		inqs[i].num_qids = max_num_hwrx_qs_per_inq;

		/* Scheduler synchronizes input queue polls. Only single thread
		* at a time polls a queue
		*/
		if (pktio_entry->s.param.in_mode == ODP_PKTIN_MODE_SCHED)
			inqs[i].lockless = 1;
		else
			inqs[i].lockless = (param->op_mode == ODP_PKTIO_OP_MT_UNSAFE);
		if (!inqs[i].lockless)
			odp_ticketlock_init(&inqs[i].lock);
	}

	return 0;
}

static int mvpp2_output_queues_config(pktio_entry_t *pktio_entry,
				      const odp_pktout_queue_param_t *param)
{
	u32 num_txq = param->num_queues;

	ODP_ASSERT(num_txq == pktio_entry->s.num_out_queue);

	/* TODO: only support now RSS; no support for QoS; how to translate rxq_id to tc/qid???? */
	if (num_txq > MVPP2_MAX_NUM_QS_PER_TC) {
		ODP_ERR("Too many output Queues configured for port (%d vs %d)\n",
			num_txq, MVPP2_MAX_NUM_QS_PER_TC);
		return -1;
	}

	/* TODO: complete!!! */

	return 0;
}

static int mvpp2_stats(pktio_entry_t *pktio_entry,
		       odp_pktio_stats_t *stats)
{
	NOTUSED(pktio_entry);
	NOTUSED(stats);
	ODP_UNIMPLEMENTED();

	return 0;
}

static int mvpp2_stats_reset(pktio_entry_t *pktio_entry)
{
	NOTUSED(pktio_entry);
	ODP_UNIMPLEMENTED();
	return 0;
}

static uint32_t mvpp2_mtu_get(pktio_entry_t *pktio_entry)
{
pr_line;
	return pktio_entry->s.pkt_mvpp2.mtu;
}

static int mvpp2_mac_get(pktio_entry_t *pktio_entry,
			 void *mac_addr)
{
	memcpy(mac_addr, pktio_entry->s.pkt_mvpp2.if_mac, ETH_ALEN);
	return ETH_ALEN;
}

static int mvpp2_promisc_mode_set(pktio_entry_t *pktio_entry,  int enable)
{
	return pp2_ppio_set_uc_promisc(pktio_entry->s.pkt_mvpp2.ppio, enable);
}

static int mvpp2_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	NOTUSED(pktio_entry);
	ODP_UNIMPLEMENTED();
	return 0;
}

static int mvpp2_link_status(pktio_entry_t *pktio_entry)
{
	/* Returns false (zero) if link is down or true(one) if link is up */
	NOTUSED(pktio_entry);
	/* TODO: implement it correctly! */
	return 1;
}

static int mvpp2_recv(pktio_entry_t *pktio_entry,
		      int rxq_id,
		      odp_packet_t pkt_table[],
		      int num_pkts)
{
	odp_packet_hdr_t	*pkt_hdr;
	odp_packet_t		 pkt;
	struct pp2_ppio_desc	 descs[CONFIG_BURST_SIZE];
	u16			 i, num, total_got, len;
#if defined(MVPP2_PKT_PARSE_SUPPORT) && (MVPP2_PKT_PARSE_SUPPORT == 1)
	enum pp2_inq_l3_type	 l3_type;
	enum pp2_inq_l4_type	 l4_type;
	u8			 l3_offset, l4_offset;
#endif /* defined(MVPP2_PKT_PARSE_SUPPORT) && ... */
	u8			 tc, qid, first_qid, num_qids;
  	u32			 tmp_num_buffs = 0;

	total_got = 0;
	if (num_pkts > (CONFIG_BURST_SIZE * MVPP2_MAX_NUM_QS_PER_TC))
		num_pkts = CONFIG_BURST_SIZE * MVPP2_MAX_NUM_QS_PER_TC;

	if (!inqs[rxq_id].lockless)
		odp_ticketlock_lock(&inqs[rxq_id].lock);

	/* TODO: only support now RSS; no support for QoS; how to translate rxq_id to tc/qid???? */
	tc = inqs[rxq_id].first_tc;
	first_qid = inqs[rxq_id].first_qid;
	num_qids = inqs[rxq_id].num_qids;
	for (qid = first_qid; qid < (first_qid + num_qids) && (total_got != num_pkts); qid++) {
		num = num_pkts - total_got;
		if (num > CONFIG_BURST_SIZE)
			num = CONFIG_BURST_SIZE;
		pp2_ppio_recv(pktio_entry->s.pkt_mvpp2.ppio, tc, qid, descs, &num);
		for (i = 0; i < num; i++, total_got++) {
			pkt_table[total_got] = (odp_packet_t)((uintptr_t)pp2_ppio_inq_desc_get_cookie(&descs[i]) |
						sys_dma_high_addr);
			len = pp2_ppio_inq_desc_get_pkt_len(&descs[i]);
#if defined(MVPP2_PKT_PARSE_SUPPORT) && (MVPP2_PKT_PARSE_SUPPORT == 1)
			pp2_ppio_inq_desc_get_l3_info(&descs[i], &l3_type, &l3_offset);
			pp2_ppio_inq_desc_get_l4_info(&descs[i], &l4_type, &l4_offset);
#endif /* defined(MVPP2_PKT_PARSE_SUPPORT) && ... */

			pkt = pkt_table[total_got];
			pkt_hdr = odp_packet_hdr(pkt);

			odp_packet_reset(pkt, len);
			/* TODO: set appropriate headroom */
			packet_parse_l2(&pkt_hdr->p, len);

#if defined(MVPP2_PKT_PARSE_SUPPORT) && (MVPP2_PKT_PARSE_SUPPORT == 1)
			odp_packet_l3_offset_set(pkt, l3_offset);
			if (odp_likely(l3_type)) {
				if (l3_type < PP2_INQ_L3_TYPE_IPV4_TTL_ZERO)
					odp_packet_has_ipv4_set(pkt, 1);
				else
					odp_packet_has_ipv6_set(pkt, 1);
				odp_packet_l4_offset_set(pkt, l4_offset);
				if (odp_likely(l4_type == PP2_INQ_L4_TYPE_TCP))
					odp_packet_has_tcp_set(pkt, 1);
				else if (odp_likely(l4_type == PP2_INQ_L4_TYPE_UDP))
					odp_packet_has_udp_set(pkt, 1);
			}
#endif /* defined(MVPP2_PKT_PARSE_SUPPORT) && ... */
			pkt_hdr->input = pktio_entry->s.handle;
		}
	}

	/* Temporary work-around : Check if we need to re-fill BPool from the SW-pool */
	pp2_bpool_get_num_buffs(pktio_entry->s.pkt_mvpp2.bpool, &tmp_num_buffs);
	if (unlikely(tmp_num_buffs <=  2 * CONFIG_BURST_SIZE)) {
		int rc;
          	rc = fill_bpool(pktio_entry->s.pkt_mvpp2.pool, pktio_entry->s.pkt_mvpp2.bpool, thds[get_thr_id()].hif,
				CONFIG_BURST_SIZE, pktio_entry->s.pkt_mvpp2.mtu);
          	if (rc < -1)
				ODP_ERR("can't fill port pool with buffs!\n");
        }

	if (!inqs[rxq_id].lockless)
		odp_ticketlock_unlock(&inqs[rxq_id].lock);

	return total_got;
}

/* An implementation for enqueuing packets */
static int mvpp2_send(pktio_entry_t *pktio_entry,
		      int txq_id,
		      const odp_packet_t pkt_table[],
		      int num_pkts)
{
	odp_packet_t		 pkt;
	odp_packet_hdr_t	*pkt_hdr;
	struct pp2_hif		*hif;
#ifndef USE_HW_BUFF_RECYLCE
	struct tx_shadow_q	*shadow_q;
#endif /* !USE_HW_BUFF_RECYLCE */
	struct pp2_ppio_desc	 descs[CONFIG_BURST_SIZE];
	dma_addr_t		 pa;
	u16			 i, num, len;
#ifndef USE_HW_BUFF_RECYLCE
	u16			 num_conf;
#endif /* !USE_HW_BUFF_RECYLCE */
	u8			 tc;
	int			 err;
#ifdef USE_LPBK_SW_RECYLCE
	u16 buf_index = 0, num_bufs = 0;
	struct buff_release_entry buff_array[MVPP2_Q_SIZE];
#endif


	/* TODO: only support now RSS; no support for QoS; how to translate txq_id to tc/hif???? */
	tc = 0;
	NOTUSED(txq_id);

	hif = thds[get_thr_id()].hif;
#ifndef USE_HW_BUFF_RECYLCE
	shadow_q = &thds[get_thr_id()].shadow_qs[tc];
#endif /* !USE_HW_BUFF_RECYLCE */

	num = num_pkts;
	if (num > CONFIG_BURST_SIZE)
		num = CONFIG_BURST_SIZE;

	for (i = 0; i < num; i++) {
		pkt = pkt_table[i];
		if (!pkt)
			continue;
		len = odp_packet_len(pkt);
		pkt_hdr = odp_packet_hdr(pkt);
		pa = mv_sys_dma_mem_virt2phys((void *)((uintptr_t)odp_packet_head(pkt)));
		pp2_ppio_outq_desc_reset(&descs[i]);
		pp2_ppio_outq_desc_set_phys_addr(&descs[i], pa);
		pp2_ppio_outq_desc_set_pkt_offset(&descs[i], odp_packet_headroom(pkt));
		pp2_ppio_outq_desc_set_pkt_len(&descs[i], len);

#if defined(MVPP2_CSUM_OFF_SUPPORT) && (MVPP2_CSUM_OFF_SUPPORT == 1)
		/* Update the slot for csum_offload */
		if (odp_likely(pkt_hdr->p.l3_offset != ODP_PACKET_OFFSET_INVALID)) {
			enum pp2_outq_l3_type l3_type =
				pkt_hdr->p.input_flags.ipv4 ? PP2_OUTQ_L3_TYPE_IPV4 :
				pkt_hdr->p.input_flags.ipv6 ? PP2_OUTQ_L3_TYPE_IPV6 : PP2_OUTQ_L3_TYPE_OTHER;

			if (odp_likely((l3_type != PP2_OUTQ_L3_TYPE_OTHER) &&
				       (pkt_hdr->p.l4_offset != ODP_PACKET_OFFSET_INVALID))) {
				if (odp_likely(pkt_hdr->p.input_flags.tcp))
					pp2_ppio_outq_desc_set_proto_info(&descs[i],
									  l3_type,
									  PP2_OUTQ_L4_TYPE_TCP,
									  pkt_hdr->p.l3_offset,
									  pkt_hdr->p.l4_offset,
									  1,
									  1);
				else if (odp_likely(pkt_hdr->p.input_flags.udp))
					pp2_ppio_outq_desc_set_proto_info(&descs[i],
									  l3_type,
									  PP2_OUTQ_L4_TYPE_UDP,
									  pkt_hdr->p.l3_offset,
									  pkt_hdr->p.l4_offset,
									  1,
									  1);
				else
					pp2_ppio_outq_desc_set_proto_info(&descs[i],
									  l3_type,
									  PP2_OUTQ_L4_TYPE_OTHER,
									  pkt_hdr->p.l3_offset,
									  pkt_hdr->p.l4_offset,
									  1,
									  0);
			}
		}
#endif /* defined(MVPP2_CSUM_OFF_SUPPORT) && ... */

#ifdef USE_HW_BUFF_RECYLCE
		pp2_ppio_outq_desc_set_cookie(&descs[i], lower_32_bits((u64)(uintptr_t)pkt));
		pp2_ppio_outq_desc_set_pool(&descs[i], pktio_entry->s.pkt_mvpp2.bpool);
#else
		shadow_q->buffs_inf[shadow_q->write_ind].cookie = lower_32_bits((u64)(uintptr_t)pkt);
		shadow_q->buffs_inf[shadow_q->write_ind].addr = pa;
		shadow_q->write_ind++;
		if (shadow_q->write_ind == MVPP2_Q_SIZE)
			shadow_q->write_ind = 0;
#endif /* USE_HW_BUFF_RECYLCE */
	}
	err = pp2_ppio_send(pktio_entry->s.pkt_mvpp2.ppio, hif, tc, descs, &num);
	if (num && (err != 0))
		return 0;

#ifndef USE_HW_BUFF_RECYLCE
	pp2_ppio_get_num_outq_done(pktio_entry->s.pkt_mvpp2.ppio, hif, tc, &num_conf);
#ifndef USE_LPBK_SW_RECYLCE
	for (i = 0; i < num_conf; i++) {
		struct pp2_buff_inf	*binf;

		binf = &shadow_q->buffs_inf[shadow_q->read_ind];
		if (unlikely(!binf->cookie || !binf->addr)) {
			ODP_ERR("Shadow memory @%d: cookie(%lx), pa(%lx)!\n",
				shadow_q->read_ind, (u64)binf->cookie, (u64)binf->addr);
			continue;
		}
		shadow_q->read_ind++;
		if (shadow_q->read_ind == MVPP2_Q_SIZE)
			shadow_q->read_ind = 0;
		pkt_hdr = odp_packet_hdr((odp_packet_t)((uintptr_t)binf->cookie | sys_dma_high_addr));
		if (likely(pkt_hdr->input)) {
			pp2_bpool_put_buff(hif, get_pktio_entry(pkt_hdr->input)->s.pkt_mvpp2.bpool, binf);
		} else {
			pkt = (odp_packet_t)((uintptr_t)binf->cookie | sys_dma_high_addr);
			odp_packet_free_multi(&pkt, 1);
		}
	}
#else
	for (i = 0; i < num_conf; i++) {
		struct pp2_buff_inf	*binf;
		binf = &shadow_q->buffs_inf[shadow_q->read_ind];
		if (unlikely(!binf->cookie || !binf->addr)) {
			ODP_ERR("Shadow memory @%d: cookie(%lx), pa(%lx)!\n",
				shadow_q->read_ind, (u64)binf->cookie, (u64)binf->addr);
			goto skip_buf;
		}
		pkt_hdr = odp_packet_hdr((odp_packet_t)((uintptr_t)binf->cookie | sys_dma_high_addr));
		if (unlikely(!(pkt_hdr->input))) {
			pkt = (odp_packet_t)((uintptr_t)binf->cookie | sys_dma_high_addr);
			odp_packet_free_multi(&pkt, 1);
			goto skip_buf;
		}

		memcpy(&buff_array[buf_index].buff, binf, sizeof(*binf));
		buff_array[buf_index].bpool= get_pktio_entry(pkt_hdr->input)->s.pkt_mvpp2.bpool;
		buf_index++;
		num_bufs++;
skip_buf:
		shadow_q->read_ind++;
		if (shadow_q->read_ind == MVPP2_Q_SIZE) {
			shadow_q->read_ind = 0;
			pp2_bpool_put_buffs(hif, buff_array, &num_bufs);
			num_bufs = 0;
			buf_index = 0;
		}
	}
	pp2_bpool_put_buffs(hif, buff_array, &num_bufs);

#endif /* USE_LPBK_SW_RECYLCE */
#endif /* !USE_HW_BUFF_RECYLCE */

	return num;
}

const pktio_if_ops_t mvpp2_pktio_ops = {
	.name = "odp-mvpp2",
	.print = NULL,
	.init_global = mvpp2_init_global,
	.init_local = mvpp2_init_local,
	.term = mvpp2_term_global,
	.open = mvpp2_open,
	.close = mvpp2_close,
	.start = mvpp2_start,
	.stop = mvpp2_stop,
	.capability = mvpp2_capability,
	.config = NULL,
	.input_queues_config = mvpp2_input_queues_config,
	.output_queues_config = mvpp2_output_queues_config,
	.stats = mvpp2_stats,
	.stats_reset = mvpp2_stats_reset,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.mtu_get = mvpp2_mtu_get,
	.promisc_mode_set = mvpp2_promisc_mode_set,
	.promisc_mode_get = mvpp2_promisc_mode_get,
	.mac_get = mvpp2_mac_get,
	.link_status = mvpp2_link_status,
	.recv = mvpp2_recv,
	.send = mvpp2_send,
};

#endif /* ODP_PKTIO_MVPP2 */
