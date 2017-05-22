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
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>


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
#define MAX_NUM_PACKPROCS		1
#define BUFFER_RELEASE_BURST_SIZE	128
#define PP2_SYSFS_RSS_PATH		"/sys/devices/platform/pp2/rss"
#define PP2_SYSFS_RSS_NUM_TABLES_FILE	"num_rss_tables"
#define PP2_MAX_BUF_STR_LEN		256

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

/* Per thread unique ID used during run-time BM and HIF
 * resource indexing
 */
struct thd_info {
	int			 id;
	struct pp2_hif		*hif;
};

static uint32_t		 used_bpools = MVPP2_BPOOL_RSRV;

/* Global lock used for control containers and other accesses */
static odp_ticketlock_t thrs_lock;
/* Per thread unique ID used during run-time BM and HIF
 * resource indexing
 */
static __thread int pp2_thr_id;
static struct thd_info		 thds[MVPP2_TOTAL_NUM_HIFS] = {};

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

static int mvpp2_sysfs_param_get(char *file)
{
	FILE *fp;
	char buf[PP2_MAX_BUF_STR_LEN];
	u32 param = 0, scanned;
	char * buf_p;

	fp = fopen(file, "r");
	if (!fp) {
		ODP_ERR("error opening file %s\n", file);
		return -1;
	}

	buf_p = fgets(buf, sizeof(buf), fp);
	if (!buf_p) {
		ODP_ERR("fgets error trying to read sysfs\n");
		fclose(fp);
		return -1;
	}

	scanned = sscanf(buf, "%d\n", &param);
	if (scanned != 1) {
		ODP_ERR("Invalid number of parameters read %s\n", buf);
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return param;
}

static int mvpp2_rss_type_get(int hash_enable, odp_pktin_hash_proto_t hash_proto)
{
	/* TODO: once MUSDK API allows to configure hash per proto, need to change this
	 * function accordingly */
	if (hash_enable) {
		if (hash_proto.proto.ipv4 ||
		    hash_proto.proto.ipv6)
			return PP2_PPIO_HASH_T_2_TUPLE;

		if (hash_proto.proto.ipv4_udp ||
		    hash_proto.proto.ipv6_udp ||
		    hash_proto.proto.ipv4_tcp ||
		    hash_proto.proto.ipv6_tcp)
			return PP2_PPIO_HASH_T_5_TUPLE;
	}

	return PP2_PPIO_HASH_T_NONE;
}

static int mvpp2_free_buf(odp_buffer_t buf)
{
	odp_packet_t pkt = _odp_packet_from_buffer(buf);
	struct pp2_buff_inf buff_inf;
	odp_packet_hdr_t *pkt_hdr;
	struct pp2_hif	*hif = thds[get_thr_id()].hif;
	int err;

	pkt_hdr = odp_packet_hdr(pkt);

	if (unlikely(!pkt_hdr)) {
		ODP_ERR("mvpp2_free_buf: invalid pkt!\n");
		return -1;
	}

	if (unlikely(!pkt_hdr->input)) {
		ODP_ERR("mvpp2_free_buf: invalid input! frame_len: %d\n", pkt_hdr->frame_len);
		return -1;
	}

	buff_inf.cookie =
			lower_32_bits((u64)(uintptr_t)pkt); /* cookie contains lower_32_bits of the va */
	buff_inf.addr   =
		(bpool_dma_addr_t)mv_sys_dma_mem_virt2phys(odp_packet_head(pkt));
	err = pp2_bpool_put_buff(hif, get_pktio_entry(pkt_hdr->input)->s.pkt_mvpp2.bpool, &buff_inf);

	return err;
}

static int fill_bpool(odp_pool_t	 pool,
		      struct pp2_bpool	*bpool,
		      struct pp2_hif	*hif,
		      int		 num,
		      int		 alloc_len)
{
	int			 i, err = 0;
	odp_packet_hdr_t	*pkt_hdr;
#ifndef USE_LPBK_SW_RECYLCE
	odp_packet_t		 pkt;
	struct pp2_buff_inf	 buff_inf;
#else
	odp_packet_t		 *pkt;
	struct buff_release_entry buff_array[MVPP2_TXQ_SIZE];
	int j = 0, err2 = 0;
	u16 final_num, num_bufs;
#endif


#ifndef USE_LPBK_SW_RECYLCE
	for (i = 0; i < num; i++) {
		pkt = odp_packet_alloc(pool, alloc_len);
		if (pkt == ODP_PACKET_INVALID) {
			ODP_ERR("Allocated invalid pkt; skipping!\n");
			continue;
		}

		if (!odp_packet_head(pkt)) {
			ODP_ERR("Allocated invalid pkt (no buffer)!\n");
			continue;
		}
		pkt_hdr = odp_packet_hdr(pkt);
		if (pkt_hdr->buf_hdr.ext_buf_free_cb) {
			ODP_ERR("pkt(%p)  ext_buf_free_cb was set; skipping\n", pkt);
			continue;
		}
		pkt_hdr->buf_hdr.ext_buf_free_cb = mvpp2_free_buf;

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
	while ((i < final_num) && (pkt[i] == ODP_PACKET_INVALID)) {
		ODP_ERR("Allocated invalid pkt, pkt_num %d out of %d; skipping!\n", i, final_num);
		i++;
	}
	if (unlikely(i == final_num)) {
		err = -1;
		goto err;
	}

	for (; i < final_num; i++) {
		if (pkt[i] == ODP_PACKET_INVALID) {
			ODP_ERR("Allocated invalid pkt; skipping!\n");
			continue;
		}

		if (!odp_packet_head(pkt[i])) {
			ODP_ERR("Allocated invalid pkt (no buffer)!\n");
			continue;
		}

		pkt_hdr = odp_packet_hdr(pkt[i]);
		if (pkt_hdr->buf_hdr.ext_buf_free_cb) {
			ODP_ERR("pkt(%p)  ext_buf_free_cb was set; skipping\n", pkt[i]);
			continue;
		}
		pkt_hdr->buf_hdr.ext_buf_free_cb = mvpp2_free_buf;

		buff_array[j].bpool = bpool;
		buff_array[j].buff.cookie =
			lower_32_bits((u64)(uintptr_t)pkt[i]); /* cookie contains lower_32_bits of the va */
		buff_array[j].buff.addr =
			(bpool_dma_addr_t)mv_sys_dma_mem_virt2phys(odp_packet_head(pkt[i]));
		j++;
		if (j == MVPP2_TXQ_SIZE) {
			num_bufs = j;
			err2 = pp2_bpool_put_buffs(hif, buff_array, &num_bufs);
			j = 0;
		}
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
	char			file[PP2_MAX_BUF_STR_LEN];
	int			num_rss_tables;


	/* Master thread. Init locks */
	odp_ticketlock_init(&thrs_lock);

	memset(&pp2_params, 0, sizeof(pp2_params));
	/* TODO: the following lines should be dynamic! */
	pp2_params.hif_reserved_map = MVPP2_HIF_RSRV;
	pp2_params.bm_pool_reserved_map = MVPP2_BPOOL_RSRV;

	sprintf(file, "%s/%s", PP2_SYSFS_RSS_PATH, PP2_SYSFS_RSS_NUM_TABLES_FILE);
	num_rss_tables = mvpp2_sysfs_param_get(file);
	pp2_params.rss_tbl_reserved_map = (1 << num_rss_tables) - 1;

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
	hif_params.out_size = MVPP2_TXQ_SIZE;
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
	capa->set_op.op.promisc_mode = true;
	odp_pktio_config_init(&capa->config);

	/* L3, L4 checksum offload on TX */
	capa->config.pktout.bit.ipv4_chksum = 1;
	capa->config.pktout.bit.udp_chksum = 1;
	capa->config.pktout.bit.tcp_chksum = 1;
	/* TODO - need to check if HW perfrom checksum generation for this type
	* capa->config.pktout.bit.sctp_chksum = 1;
	*/

	/* L3, L4 checksum offload on RX */
	capa->config.pktin.bit.ipv4_chksum = 1;
	capa->config.pktin.bit.udp_chksum = 1;
	capa->config.pktin.bit.tcp_chksum = 1;
	/* HW alwyas generate checksum error for non UDP/TCP frames
	* capa->config.pktin.bit.sctp_chksum = 1;
	*/
	capa->config.pktin.bit.drop_ipv4_err = 1;
	/* TODO - probably need to parse it in SW to support it
	* capa->config.pktin.bit.drop_ipv6_err = 1;
	*/
	capa->config.pktin.bit.drop_udp_err = 1;
	capa->config.pktin.bit.drop_tcp_err = 1;
	/* TODO - need to check if HW perfrom checksum validation for this type.
	* if so, in SW need to identify it by looking at ip-protocol.
	* capa->config.pktin.bit.drop_sctp_err = 1;
	*/
}

static int mvpp2_open(odp_pktio_t pktio ODP_UNUSED,
		      pktio_entry_t *pktio_entry,
		      const char *devname,
		      odp_pool_t pool)
{
	struct pp2_bpool_params		bpool_params;
	port_desc_t			port_desc;
	char				name[15];
	int				err, pool_id;

	if (strlen(devname) > sizeof(name) - 1) {
		ODP_ERR("Port name (%s) too long!\n", devname);
		return -1;
	}

	memset(&port_desc, 0, sizeof(port_desc));

	/* Set port name to pktio_entry */
	snprintf(pktio_entry->s.name, sizeof(pktio_entry->s.name), "%s", devname);

	port_desc.name = pktio_entry->s.name;
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

	memset(pktio_entry->s.pkt_mvpp2.shadow_qs, 0, sizeof(pktio_entry->s.pkt_mvpp2.shadow_qs));

	return 0;
}

static int mvpp2_close(pktio_entry_t *pktio_entry)
{
	/* Close (destroy) the PP2 port */
	pp2_ppio_deinit(pktio_entry->s.pkt_mvpp2.ppio);
	ODP_DBG("port '%s' was closed\n", pktio_entry->s.name);
	return 0;
}

static int mvpp2_start(pktio_entry_t *pktio_entry)
{
	char				name[15];
	port_desc_t			port_desc;
	int				i, j, err;
	struct pp2_ppio_params		port_params;
	struct pp2_ppio_inq_params	inq_params[MVPP2_MAX_NUM_QS_PER_TC];

	if (!pktio_entry->s.num_in_queue && !pktio_entry->s.num_out_queue) {
		ODP_ERR("No input and output queues configured!\n");
		return -1;
	}

	port_desc.name = pktio_entry->s.name;
	err = find_port_info(&port_desc);
	if (err != 0) {
		ODP_ERR("Port info not found!\n");
		return -1;
	}

	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "ppio-%d:%d", port_desc.pp_id, port_desc.ppio_id);
	memset(&port_params, 0, sizeof(port_params));
	port_params.match = name;
	port_params.type = PP2_PPIO_T_NIC;

	port_params.inqs_params.hash_type = pktio_entry->s.pkt_mvpp2.hash_type;
	ODP_DBG("hash_type %d\n", port_params.inqs_params.hash_type);

	port_params.inqs_params.num_tcs = MVPP2_MAX_NUM_TCS_PER_PORT;
	for (i = 0; i < port_params.inqs_params.num_tcs; i++) {
		port_params.inqs_params.tcs_params[i].pkt_offset = MVPP2_PACKET_OFFSET >> 2;
		port_params.inqs_params.tcs_params[i].num_in_qs = pktio_entry->s.num_in_queue;
		memset(inq_params, 0, sizeof(inq_params));
		for (j = 0; j < port_params.inqs_params.tcs_params[i].num_in_qs; j++)
			inq_params[j].size = MVPP2_RXQ_SIZE;
		port_params.inqs_params.tcs_params[i].inqs_params = inq_params;
		port_params.inqs_params.tcs_params[i].pools[0] = pktio_entry->s.pkt_mvpp2.bpool;
	}
	port_params.outqs_params.num_outqs = MVPP2_MAX_NUM_TCS_PER_PORT;
	for (i = 0; i < port_params.outqs_params.num_outqs; i++) {
		port_params.outqs_params.outqs_params[i].size = MVPP2_TXQ_SIZE;
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

	pp2_ppio_enable(pktio_entry->s.pkt_mvpp2.ppio);

	ODP_PRINT("PktIO PP2 has %d RxTCs and %d TxTCs\n",
		  MVPP2_MAX_NUM_TCS_PER_PORT,
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
	pp2_ppio_disable(pktio_entry->s.pkt_mvpp2.ppio);
	ODP_DBG("port '%s' was stopped\n", pktio_entry->s.name);
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
	u32	 i;
	u8	 max_num_hwrx_qs_per_inq;
	u32	 num_rxq = param->num_queues;

	ODP_ASSERT(num_rxq == pktio_entry->s.num_in_queue);

	/* TODO: only support now RSS; no support for QoS; how to translate rxq_id to tc/qid???? */
	max_num_hwrx_qs = (MVPP2_MAX_NUM_TCS_PER_PORT * MVPP2_MAX_NUM_QS_PER_TC);
	if (pktio_entry->s.num_in_queue > max_num_hwrx_qs) {
		ODP_ERR("Too many In-Queues mapped (%d vs %d)!\n",
			pktio_entry->s.num_in_queue,
			max_num_hwrx_qs);
		return -1;
	}

	max_num_hwrx_qs_per_inq = 1;	/* each logical queue is mapped to one phy queue */
	for (i = 0; i < pktio_entry->s.num_in_queue; i++) {
		pktio_entry->s.pkt_mvpp2.inqs[i].first_tc = 0;
		pktio_entry->s.pkt_mvpp2.inqs[i].num_tcs = 1;
		pktio_entry->s.pkt_mvpp2.inqs[i].first_qid = (i * max_num_hwrx_qs_per_inq);
		pktio_entry->s.pkt_mvpp2.inqs[i].next_qid = pktio_entry->s.pkt_mvpp2.inqs[i].first_qid;
		pktio_entry->s.pkt_mvpp2.inqs[i].num_qids = max_num_hwrx_qs_per_inq;
		ODP_DBG("inqs[%d] first_qid %d, num_qids %d\n", i, pktio_entry->s.pkt_mvpp2.inqs[i].first_qid,
		       pktio_entry->s.pkt_mvpp2.inqs[i].num_qids);

		/* Scheduler synchronizes input queue polls. Only single thread
		* at a time polls a queue
		*/
		if (pktio_entry->s.param.in_mode == ODP_PKTIN_MODE_SCHED)
			pktio_entry->s.pkt_mvpp2.inqs[i].lockless = 1;
		else
			pktio_entry->s.pkt_mvpp2.inqs[i].lockless = (param->op_mode == ODP_PKTIO_OP_MT_UNSAFE);
		if (!pktio_entry->s.pkt_mvpp2.inqs[i].lockless)
			odp_ticketlock_init(&pktio_entry->s.pkt_mvpp2.inqs[i].lock);
	}

	/* RSS support */
	pktio_entry->s.pkt_mvpp2.hash_type = mvpp2_rss_type_get(param->hash_enable, param->hash_proto);

	return 0;
}

static int mvpp2_output_queues_config(pktio_entry_t *pktio_entry,
				      const odp_pktout_queue_param_t *param)
{
	int	i, j;
	u32	max_num_hwrx_qs, num_txq = param->num_queues;

	ODP_ASSERT(num_txq == pktio_entry->s.num_out_queue);

	/* TODO: only support now RSS; no support for QoS; how to translate rxq_id to tc/qid???? */
	max_num_hwrx_qs = (MVPP2_MAX_NUM_TCS_PER_PORT * MVPP2_MAX_NUM_QS_PER_TC);
	if (pktio_entry->s.num_out_queue > max_num_hwrx_qs) {
		ODP_ERR("Too many Out-Queues mapped (%d vs %d)!\n",
			pktio_entry->s.num_out_queue,
			max_num_hwrx_qs);
		return -1;
	}

	for (i = 0; i < MVPP2_TOTAL_NUM_HIFS; i++) {
		for (j = 0; j < MAX_NUM_OUTQS_PER_CORE; j++) {
			if (pktio_entry->s.param.out_mode == ODP_PKTOUT_MODE_TM)
				pktio_entry->s.pkt_mvpp2.shadow_qs[i][j].lockless = 1;
			else
				pktio_entry->s.pkt_mvpp2.shadow_qs[i][j].lockless =
					(param->op_mode == ODP_PKTIO_OP_MT_UNSAFE);
			if (!pktio_entry->s.pkt_mvpp2.shadow_qs[i][j].lockless)
				odp_ticketlock_init(&pktio_entry->s.pkt_mvpp2.shadow_qs[i][j].lock);
		}
	}

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
	int err;
	err = pp2_ppio_set_uc_promisc(pktio_entry->s.pkt_mvpp2.ppio, enable);
	if (err) {
		err = -1;
	}

	return err;
}

static int mvpp2_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	int err, enable = 0;

	err = pp2_ppio_get_uc_promisc(pktio_entry->s.pkt_mvpp2.ppio, &enable);
	if (err) {
		enable = -1;
	}

	return enable;
}

static int mvpp2_link_status(pktio_entry_t *pktio_entry)
{
	/* Returns false (zero) if link is down or true(one) if link is up */
	int err, link_up = 0;

	err = pp2_ppio_get_link_state(pktio_entry->s.pkt_mvpp2.ppio, &link_up);
	if (err) {
		link_up = -1;
	}
	return link_up;
}

#ifndef USE_HW_BUFF_RECYLCE
static inline void mvpp2_free_sent_buffers(struct pp2_ppio *ppio, struct pp2_hif *hif,
					   struct tx_shadow_q *shadow_q, u8 tc)
{
	struct buff_release_entry *entry;
	odp_packet_t pkt;
	u16 i, num_conf = 0;
#ifdef USE_LPBK_SW_RECYLCE
	u16 num_bufs = 0;
#endif

	pp2_ppio_get_num_outq_done(ppio, hif, tc, &num_conf);

	shadow_q->num_to_release += num_conf;

	if (odp_likely(shadow_q->num_to_release < BUFFER_RELEASE_BURST_SIZE))
		return;

	num_conf = shadow_q->num_to_release;
	shadow_q->num_to_release = 0;

#ifndef USE_LPBK_SW_RECYLCE
	for (i = 0; i < num_conf; i++) {
		entry = &shadow_q->ent[shadow_q->read_ind];
		if (unlikely(!entry->buff.cookie && !entry->buff.addr)) {
			ODP_ERR("Shadow memory @%d: cookie(%lx), pa(%lx)!\n",
				shadow_q->read_ind, (u64)entry->buff.cookie, (u64)entry->buff.addr);
			shadow_q->read_ind++;
			shadow_q->size--;
			if (shadow_q->read_ind == SHADOW_Q_MAX_SIZE)
				shadow_q->read_ind = 0;
			continue;
		}
		shadow_q->read_ind++;
		shadow_q->size--;
		if (shadow_q->read_ind == SHADOW_Q_MAX_SIZE)
			shadow_q->read_ind = 0;

		if (likely(entry->bpool))
			pp2_bpool_put_buff(hif, entry->bpool, &entry->buff);
		else {
			pkt = (odp_packet_t)((uintptr_t)entry->buff.cookie);
			odp_packet_free_multi(&pkt, 1);
		}
	}
#else
	for (i = 0; i < num_conf; i++) {
		entry = &shadow_q->ent[shadow_q->read_ind + num_bufs];
		if (unlikely(!entry->buff.addr)) {
			ODP_ERR("Shadow memory @%d: cookie(%lx), pa(%lx)!\n",
				shadow_q->read_ind, (u64)entry->buff.cookie, (u64)entry->buff.addr);
			goto skip_buf;
		}

		if (unlikely(!entry->bpool)) {
			pkt = (odp_packet_t)((uintptr_t)entry->buff.cookie);
			odp_packet_free_multi(&pkt, 1);
			goto skip_buf;
		}

		num_bufs++;
		if (unlikely(shadow_q->read_ind + num_bufs == SHADOW_Q_MAX_SIZE))
			goto skip_buf;
		continue;
skip_buf:
		if (num_bufs) {
			pp2_bpool_put_buffs(hif, &shadow_q->ent[shadow_q->read_ind], &num_bufs);
			shadow_q->read_ind = (shadow_q->read_ind + num_bufs) & SHADOW_Q_MAX_SIZE_MASK;
			shadow_q->size -= num_bufs;
			num_bufs = 0;
		}
	}
	if (num_bufs) {
		pp2_bpool_put_buffs(hif, &shadow_q->ent[shadow_q->read_ind], &num_bufs);
		shadow_q->read_ind = (shadow_q->read_ind + num_bufs) & SHADOW_Q_MAX_SIZE_MASK;
		shadow_q->size -= num_bufs;
	}
#endif /* USE_LPBK_SW_RECYLCE */
}
#endif /* USE_HW_BUFF_RECYLCE */

static int mvpp2_recv(pktio_entry_t *pktio_entry,
		      int rxq_id,
		      odp_packet_t pkt_table[],
		      int num_pkts)
{
	odp_packet_hdr_t	*pkt_hdr;
	odp_packet_t		 pkt;
	struct pp2_ppio_desc	 descs[MVPP2_MAX_RX_BURST_SIZE];
	u16			 i, j, num, total_got, len;
	enum pp2_inq_l3_type	 l3_type;
	enum pp2_inq_l4_type	 l4_type;
	u8			 l3_offset, l4_offset;
	u8			 tc, qid, num_qids, last_qid;
	enum pp2_inq_desc_status desc_err;

	total_got = 0;
	if (num_pkts > (MVPP2_MAX_RX_BURST_SIZE * MVPP2_MAX_NUM_QS_PER_TC))
		num_pkts = MVPP2_MAX_RX_BURST_SIZE * MVPP2_MAX_NUM_QS_PER_TC;

	if (!pktio_entry->s.pkt_mvpp2.inqs[rxq_id].lockless)
		odp_ticketlock_lock(&pktio_entry->s.pkt_mvpp2.inqs[rxq_id].lock);

	/* TODO: only support now RSS; no support for QoS; how to translate rxq_id to tc/qid???? */
	tc = pktio_entry->s.pkt_mvpp2.inqs[rxq_id].first_tc;
	qid = pktio_entry->s.pkt_mvpp2.inqs[rxq_id].next_qid;
	num_qids = pktio_entry->s.pkt_mvpp2.inqs[rxq_id].num_qids;
	last_qid = pktio_entry->s.pkt_mvpp2.inqs[rxq_id].first_qid + num_qids - 1;
	for (i = 0; (i < num_qids) && (total_got != num_pkts); i++) {
		num = num_pkts - total_got;
		if (num > MVPP2_MAX_RX_BURST_SIZE)
			num = MVPP2_MAX_RX_BURST_SIZE;
		pp2_ppio_recv(pktio_entry->s.pkt_mvpp2.ppio, tc, qid, descs, &num);
		for (j = 0; j < num; j++) {
			pkt_table[total_got] = (odp_packet_t)pp2_ppio_inq_desc_get_cookie(&descs[j]);
			len = pp2_ppio_inq_desc_get_pkt_len(&descs[j]);

			pkt = pkt_table[total_got];
			pkt_hdr = odp_packet_hdr(pkt);

			odp_packet_reset(pkt, len);
			pkt_hdr->input = pktio_entry->s.handle;
			pkt_hdr->p.parsed_layers = LAYER_ALL;

			pp2_ppio_inq_desc_get_l3_info(&descs[j], &l3_type, &l3_offset);
			pp2_ppio_inq_desc_get_l4_info(&descs[j], &l4_type, &l4_offset);

			desc_err = pp2_ppio_inq_desc_get_l2_pkt_error(&descs[j]);
			if (odp_unlikely(desc_err != PP2_DESC_ERR_OK)) {
				/* Always drop L2 errors */
				ODP_DBG("Drop packet with L2 error: %d", desc_err);
				odp_packet_free(pkt);
				continue;
			}

			desc_err = pp2_ppio_inq_desc_get_l3_pkt_error(&descs[j]);
			if (odp_unlikely(desc_err == PP2_DESC_ERR_IPV4_HDR)) {
				pkt_hdr->p.error_flags.ip_err = 1;
				if (odp_unlikely(pktio_entry->s.config.pktin.bit.ipv4_chksum == 0)) {
					/* Need to parse IPv4. if the error is actually from checksum than need to unset
					* the error flag. */
					odp_packet_l3_offset_set(pkt, l3_offset);
					if (odp_likely(!odph_ipv4_csum_valid(pkt)))
						pkt_hdr->p.error_flags.ip_err = 0;
				}
				if (odp_likely(pktio_entry->s.config.pktin.bit.drop_ipv4_err &&
					pkt_hdr->p.error_flags.ip_err)) {
					ODP_DBG("Drop packet with L3 error: %d", desc_err);
					odp_packet_free(pkt);
					continue;
				}
			}

			desc_err = pp2_ppio_inq_desc_get_l4_pkt_error(&descs[j]);
			if (odp_unlikely(desc_err == PP2_DESC_ERR_L4_CHECKSUM)) {
				pkt_hdr->p.error_flags.udp_err = ((l4_type == PP2_INQ_L4_TYPE_UDP) &&
					(pktio_entry->s.config.pktin.bit.udp_chksum));
				pkt_hdr->p.error_flags.tcp_err = ((l4_type == PP2_INQ_L4_TYPE_TCP) &&
					(pktio_entry->s.config.pktin.bit.tcp_chksum));
				if (odp_unlikely((pkt_hdr->p.error_flags.udp_err &&
						  pktio_entry->s.config.pktin.bit.drop_udp_err) ||
					(pkt_hdr->p.error_flags.tcp_err &&
					 pktio_entry->s.config.pktin.bit.drop_tcp_err))) {
					ODP_DBG("Drop packet with L4 error: %d", desc_err);
					odp_packet_free(pkt);
					continue;
				}
			}

			total_got++;
			/* TODO: set appropriate headroom */
			packet_parse_l2(&pkt_hdr->p, len);

			odp_packet_l3_offset_set(pkt, l3_offset);
			if (odp_likely(l3_type)) {
				odp_packet_has_l3_set(pkt, 1);
				if (l3_type < PP2_INQ_L3_TYPE_IPV4_TTL_ZERO)
					odp_packet_has_ipv4_set(pkt, 1);
				else
					odp_packet_has_ipv6_set(pkt, 1);
				odp_packet_l4_offset_set(pkt, l4_offset);
				if (odp_likely(l4_type))
					odp_packet_has_l4_set(pkt, 1);
				if (odp_likely(l4_type == PP2_INQ_L4_TYPE_TCP))
					odp_packet_has_tcp_set(pkt, 1);
				else if (odp_likely(l4_type == PP2_INQ_L4_TYPE_UDP))
					odp_packet_has_udp_set(pkt, 1);
			}
		}
		if (odp_unlikely(qid++ == last_qid))
			qid = pktio_entry->s.pkt_mvpp2.inqs[rxq_id].first_qid;
	}
	pktio_entry->s.pkt_mvpp2.inqs[rxq_id].next_qid = qid;
	if (!pktio_entry->s.pkt_mvpp2.inqs[rxq_id].lockless)
		odp_ticketlock_unlock(&pktio_entry->s.pkt_mvpp2.inqs[rxq_id].lock);

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
	u16			 shadow_q_free_size;
#endif /* !USE_HW_BUFF_RECYLCE */
	struct pp2_ppio_desc	 descs[MVPP2_MAX_TX_BURST_SIZE];
	dma_addr_t		 pa;
	u16			 i, num, len, idx = 0;
	u8			 tc;
	int			 err, sent = 0;
	pkt_mvpp2_t		*pkt_mvpp2 = &pktio_entry->s.pkt_mvpp2;
	pktio_entry_t 		*input_entry;
	struct odp_pktio_config_t *config = &pktio_entry->s.config;

	/* TODO: only support now RSS; no support for QoS; how to translate txq_id to tc/hif???? */
	tc = 0;
	NOTUSED(txq_id);

	hif = thds[get_thr_id()].hif;
#ifndef USE_HW_BUFF_RECYLCE
	shadow_q = &pkt_mvpp2->shadow_qs[get_thr_id()][tc];
	if (!shadow_q->lockless)
		odp_ticketlock_lock(&shadow_q->lock);
	if (shadow_q->size)
		mvpp2_free_sent_buffers(pkt_mvpp2->ppio, hif, shadow_q, tc);

	shadow_q_free_size = SHADOW_Q_MAX_SIZE - shadow_q->size - 1;
	if (odp_unlikely(num_pkts >= shadow_q_free_size)) {
		ODP_ERR("No room in shadow queue for %d packets!!! %d packets will be sent.\n",
			num_pkts, shadow_q_free_size);
		num_pkts = shadow_q_free_size;
	}
#endif /* !USE_HW_BUFF_RECYLCE */

	for (i = 0; i < num_pkts; i++) {
		pkt = pkt_table[i];
		len = odp_packet_len(pkt);
		pkt_hdr = odp_packet_hdr(pkt);
		pa = mv_sys_dma_mem_virt2phys((void *)((uintptr_t)odp_packet_head(pkt)));
		pp2_ppio_outq_desc_reset(&descs[idx]);
		pp2_ppio_outq_desc_set_phys_addr(&descs[idx], pa);
		pp2_ppio_outq_desc_set_pkt_offset(&descs[idx], odp_packet_headroom(pkt));
		pp2_ppio_outq_desc_set_pkt_len(&descs[idx], len);

		/* Update the slot for csum_offload */
		if (odp_likely(pkt_hdr->p.l3_offset != ODP_PACKET_OFFSET_INVALID)) {
			enum pp2_outq_l3_type l3_type =
				pkt_hdr->p.input_flags.ipv4 ? PP2_OUTQ_L3_TYPE_IPV4 :
				pkt_hdr->p.input_flags.ipv6 ? PP2_OUTQ_L3_TYPE_IPV6 : PP2_OUTQ_L3_TYPE_OTHER;

			if (odp_likely((l3_type != PP2_OUTQ_L3_TYPE_OTHER) &&
				       (pkt_hdr->p.l4_offset != ODP_PACKET_OFFSET_INVALID))) {
				if (odp_likely(pkt_hdr->p.input_flags.tcp))
					pp2_ppio_outq_desc_set_proto_info(&descs[idx],
									  l3_type,
									  PP2_OUTQ_L4_TYPE_TCP,
									  pkt_hdr->p.l3_offset,
									  pkt_hdr->p.l4_offset,
									  config->pktout.bit.ipv4_chksum,
									  config->pktout.bit.tcp_chksum);
				else if (odp_likely(pkt_hdr->p.input_flags.udp))
					pp2_ppio_outq_desc_set_proto_info(&descs[idx],
									  l3_type,
									  PP2_OUTQ_L4_TYPE_UDP,
									  pkt_hdr->p.l3_offset,
									  pkt_hdr->p.l4_offset,
									  config->pktout.bit.ipv4_chksum,
									  config->pktout.bit.udp_chksum);
				else
					pp2_ppio_outq_desc_set_proto_info(&descs[idx],
									  l3_type,
									  PP2_OUTQ_L4_TYPE_OTHER,
									  pkt_hdr->p.l3_offset,
									  pkt_hdr->p.l4_offset,
									  1,
									  0);
			}
		}

#ifdef USE_HW_BUFF_RECYLCE
		pp2_ppio_outq_desc_set_cookie(&descs[idx], lower_32_bits((u64)(uintptr_t)pkt));
		pp2_ppio_outq_desc_set_pool(&descs[idx], pktio_entry->s.pkt_mvpp2.bpool);
#else
		shadow_q->ent[shadow_q->write_ind].buff.cookie = lower_32_bits((u64)(uintptr_t)pkt);
		shadow_q->ent[shadow_q->write_ind].buff.addr = pa;

		input_entry = get_pktio_entry(pkt_hdr->input);
		if (odp_likely(input_entry && input_entry->s.ops == &mvpp2_pktio_ops))
			shadow_q->ent[shadow_q->write_ind].bpool = input_entry->s.pkt_mvpp2.bpool;
		else
			shadow_q->ent[shadow_q->write_ind].bpool = NULL;

		shadow_q->write_ind = (shadow_q->write_ind + 1) & SHADOW_Q_MAX_SIZE_MASK;
		shadow_q->size++;
		if (!shadow_q->lockless)
			odp_ticketlock_unlock(&shadow_q->lock);
#endif /* USE_HW_BUFF_RECYLCE */
		idx++;
		if (odp_unlikely(idx == MVPP2_MAX_TX_BURST_SIZE)) {
			num = idx;
			err = pp2_ppio_send(pkt_mvpp2->ppio, hif, tc, descs, &num);
			sent += num;
			if ((idx != num) || (err != 0))
				return sent;
			idx = 0;
		}
	}
	err = pp2_ppio_send(pkt_mvpp2->ppio, hif, tc, descs, &idx);
	sent += idx;

	return sent;
}

static int mvpp2_config(pktio_entry_t *pktio_entry ODP_UNUSED, const odp_pktio_config_t *config)
{
	ODP_PRINT("RX checksum offload configuration: IPv4 (%u), UDP (%u), TCP (%u), SCTP (%u)\n",
		config->pktin.bit.ipv4_chksum, config->pktin.bit.udp_chksum,
		config->pktin.bit.tcp_chksum, config->pktin.bit.sctp_chksum);
	ODP_PRINT("TX checksum offload configuration: IPv4 (%u), UDP (%u), TCP (%u), SCTP (%u)\n",
		config->pktout.bit.ipv4_chksum, config->pktout.bit.udp_chksum,
		config->pktout.bit.tcp_chksum, config->pktout.bit.sctp_chksum);
	ODP_PRINT("RX Dropping offload capability: IPv4 (%u), UDP (%u), TCP (%u), SCTP (%u)\n",
		config->pktin.bit.drop_ipv4_err, config->pktin.bit.drop_udp_err,
		config->pktin.bit.drop_tcp_err, config->pktin.bit.drop_sctp_err);

	/* TODO: Verify if RX DMA can be configure to drop on checksum error, by calling a proper MuSDK API.*/

	return 0;
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
	.config = mvpp2_config,
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
