/* Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp_musdk_internal.h>
#include <odp_debug_internal.h>
#include <protocols/eth.h>
#include <protocols/ip.h>
#include <protocols/tcp.h>
#include <protocols/udp.h>

/* prefetch=2, tested to be optimal both for
   mvgiu_recv() & mvgiu_send() prefetch operations */
#define MVGIU_PREFETCH_SHIFT		2
#define MAX_BUFFER_GET_RETRIES		10000

static u64	sys_dma_high_addr;

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define MVGIU_NO_HEADROOM
#define MVGIU_SW_PARSE

#ifdef ODP_MVNMP
extern struct nmp *nmp;

extern void nmp_schedule_all(struct nmp *nmp);
#endif

static int mvgiu_free_buf(odp_buffer_t buf)
{
	odp_packet_t pkt = _odp_packet_from_buffer(buf);
	odp_packet_hdr_t *pkt_hdr;
	pktio_entry_t *pktio_entry;
	struct mvgiu_bufs_stockpile *bufs_stockpile;
	int err = 0;

	pkt_hdr = odp_packet_hdr(pkt);

	if (unlikely(!pkt_hdr)) {
		ODP_ERR("mvgiu_free_buf: invalid pkt!\n");
		return -1;
	}

	if (unlikely(!pkt_hdr->input)) {
		ODP_ERR("mvgiu_free_buf: invalid input!\n");
		return -1;
	}

	if (pkt_hdr->buf_hdr.size == 0) {
		ODP_ERR("mvgiu_free_buf: invalid buf size!\n");
		return -1;
	}

	pktio_entry = get_pktio_entry(pkt_hdr->input);
	if (unlikely(pktio_entry &&
		     pktio_entry->s.state == PKTIO_STATE_FREE)) {
		/* In case input pktio is in 'free' state, it means it was
		 * already closed and this buffer was saved in other pktio's
		 * tx queue. Therefor the buffer should be return to the
		 * ODP-POOL instead of the HW-Pool. this can be achevied by
		 * returning a non-zero return code.
		 */
		ODP_DBG("mvpp2_free_buf: pktio was closed! "
			"return the pkt to odp-pool\n");
		return 1;
	}

	pkt_hdr->input = NULL;

	bufs_stockpile =
		&pktio_entry->s.pkt_mvgiu.bufs_stockpile;
	bufs_stockpile->ent[bufs_stockpile->size].cookie = (u64)pkt;
#ifdef MVGIU_NO_HEADROOM
	odp_packet_reset(pkt, pkt_hdr->frame_len);
	bufs_stockpile->ent[bufs_stockpile->size++].addr =
		mv_sys_dma_mem_virt2phys(odp_packet_data(pkt));
#else
	bufs_stockpile->ent[bufs_stockpile->size++].addr =
		mv_sys_dma_mem_virt2phys(odp_packet_head(pkt));
#endif
	if (bufs_stockpile->size == BUFFER_RELEASE_BURST_SIZE) {
		err = giu_bpool_put_buffs(pktio_entry->s.pkt_mvgiu.bpool,
					  bufs_stockpile->ent,
					  &bufs_stockpile->size);
		bufs_stockpile->size = 0;
	}
	return err;
}

static inline void mvgiu_free_sent_buffers(struct mvgiu_tx_shadow_q *shadow_q)
{
	struct giu_buff_inf *entry;
	struct giu_bpool *bpool;
	pktio_entry_t *pktio_entry;
	odp_pktio_t pktio;
	odp_packet_t pkt;
	u16 i, num_conf = 0, num_bufs = 0, skip_bufs = 0;

	num_conf = shadow_q->num_to_release;
	shadow_q->num_to_release = 0;

	for (i = 0; i < num_conf; i++) {
		entry = &shadow_q->ent[shadow_q->read_ind + num_bufs];
		bpool = shadow_q->bpool[shadow_q->read_ind + num_bufs];
		if (unlikely(!entry->addr)) {
			ODP_ERR("Shadow memory @%d: cookie(%lx), pa(%lx)!\n",
				shadow_q->read_ind, (u64)entry->cookie,
				(u64)entry->addr);
			skip_bufs = 1;
			goto skip_buf;
		}

		if (unlikely(!bpool)) {
			pkt = (odp_packet_t)((uintptr_t)entry->cookie);
			odp_packet_free(pkt);
			skip_bufs = 1;
			goto skip_buf;
		}

		pktio = shadow_q->input_pktio[shadow_q->read_ind + num_bufs];
		pktio_entry = get_pktio_entry(pktio);
		if (unlikely(pktio_entry &&
			     pktio_entry->s.state == PKTIO_STATE_FREE)) {
			/* In case input pktio is in 'free' state, it means it
			 * was already closed and this buffer should be return
			 * to the ODP-POOL instead of the HW-Pool
			 */
			pkt = (odp_packet_t)((uintptr_t)entry->cookie);
			odp_packet_hdr(pkt)->buf_hdr.ext_buf_free_cb = NULL;
			odp_packet_free(pkt);
			skip_bufs = 1;
			goto skip_buf;
		}

		num_bufs++;
		if (unlikely(shadow_q->read_ind + num_bufs ==
			     SHADOW_Q_MAX_SIZE))
			goto skip_buf;
		continue;

skip_buf:
		if (num_bufs)
			giu_bpool_put_buffs(shadow_q->bpool[shadow_q->read_ind],
					    &shadow_q->ent[shadow_q->read_ind],
					    &num_bufs);
		num_bufs += skip_bufs;
		shadow_q->read_ind = (shadow_q->read_ind + num_bufs) &
				     SHADOW_Q_MAX_SIZE_MASK;
		shadow_q->size -= num_bufs;
		num_bufs = 0;
		skip_bufs = 0;
	}
	if (num_bufs) {
		giu_bpool_put_buffs(shadow_q->bpool[shadow_q->read_ind],
				    &shadow_q->ent[shadow_q->read_ind],
				    &num_bufs);
		shadow_q->read_ind = (shadow_q->read_ind + num_bufs) &
				     SHADOW_Q_MAX_SIZE_MASK;
		shadow_q->size -= num_bufs;
	}
}

static inline
void mvgiu_check_n_free_sent_buffers(struct giu_gpio *gpio,
				     struct mvgiu_tx_shadow_q *shadow_q,
				     u8 tc,
				     u8 qid)
{
	u16 num_conf = 0;

	giu_gpio_get_num_outq_done(gpio, tc, qid, &num_conf);

	shadow_q->num_to_release += num_conf;

	if (odp_likely(shadow_q->num_to_release < BUFFER_RELEASE_BURST_SIZE))
		return;

	mvgiu_free_sent_buffers(shadow_q);
}

static int fill_bpool(odp_pool_t	pool,
		      struct giu_bpool	*bpool,
		      int		num,
		      int		alloc_len)
{
	int			 i, j = 0, err = 0;
	odp_packet_hdr_t	*pkt_hdr;
	odp_packet_t		 pkt[num];
	struct giu_buff_inf buff_array[num];
	u16 final_num, num_bufs;

	final_num = packet_alloc_multi(pool, alloc_len, pkt, num);
	if (final_num != num) {
		ODP_ERR("No free packets left\n");
		goto fail;
	}

	/* set high_addr from first pkt */
	sys_dma_high_addr = ((u64)pkt[0] & SYS_DMA_HIGH_ADDR_MASK);

	for (i = 0; i < num; i++) {
		if (((u64)pkt[i] & SYS_DMA_HIGH_ADDR_MASK) !=
			sys_dma_high_addr) {
			ODP_ERR("pkt(%p) upper addr should be %p\n",
				pkt[i], (void *)sys_dma_high_addr);
			continue;
		}

		pkt_hdr = odp_packet_hdr(pkt[i]);
		if (pkt_hdr->buf_hdr.ext_buf_free_cb) {
			ODP_ERR("pkt(%p)  ext_buf_free_cb was set; skipping\n",
				pkt[i]);
			continue;
		}

		pkt_hdr->buf_hdr.ext_buf_free_cb = mvgiu_free_buf;

		buff_array[j].cookie = (u64)pkt[i];
#ifdef MVGIU_NO_HEADROOM
		buff_array[j].addr =
			mv_sys_dma_mem_virt2phys(odp_packet_data(pkt[i]));
#else
		buff_array[j].addr =
			mv_sys_dma_mem_virt2phys(odp_packet_head(pkt[i]));
#endif

		j++;
	}
	num_bufs = j;
	err = giu_bpool_put_buffs(bpool, buff_array, &num_bufs);
fail:
	return err;
}

static void flush_bpool(struct giu_bpool *bpool)
{
	u32 i, buf_num, err = 0;
	struct giu_buff_inf buff;
	odp_packet_t pkt;
	odp_packet_hdr_t *pkt_hdr;

	return;

	giu_bpool_get_num_buffs(bpool, &buf_num);
	for (i = 0; i < buf_num; i++) {
		err = 0;
		if (err) {
			if (err == MAX_BUFFER_GET_RETRIES) {
				ODP_ERR("flush_pool: pool_id=%d: "
					"Got NULL buf (%d of %d)\n",
					bpool->id, i, buf_num);
				continue;
			}
			ODP_DBG("flush_pool: pool_id=%d: Got buf "
				"(%d of %d) after %d retries\n",
				bpool->id, i, buf_num, err);
		}
		pkt = (odp_packet_t)(buff.cookie | sys_dma_high_addr);
		pkt_hdr = odp_packet_hdr(pkt);
		pkt_hdr->buf_hdr.ext_buf_free_cb = NULL;
		odp_packet_free(pkt);
	}
}

static void init_capability(pktio_entry_t *pktio_entry)
{
	odp_pktio_capability_t *capa = &pktio_entry->s.pkt_mvgiu.capa;

	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues =
		(MVGIU_MAX_NUM_TCS_PER_PORT * MVGIU_MAX_NUM_QS_PER_TC);
	capa->max_output_queues =
		(MVGIU_MAX_NUM_TCS_PER_PORT * MVGIU_MAX_NUM_QS_PER_TC);
}

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

static int mvgiu_open(odp_pktio_t pktio ODP_UNUSED,
		      pktio_entry_t *pktio_entry,
		      const char *devname,
		      odp_pool_t pool)
{
	char	file_name[REGFILE_MAX_FILE_NAME];
	char	name[20];
	int	err = 0;
	u32	buf_num;
	int	giu_id = 0; /* TODO: get this value from higher levels */
	int	bpool_id = 0; /* TODO: get this value from higher levels */
	int	gpio_id = 0; /* TODO: get this value from higher levels */
	struct giu_bpool_capabilities bpool_capa;
	struct giu_gpio_capabilities gpio_capa;

	if (strncmp(devname, "giu", 3) != 0)
		return -1;

	/* Init pktio entry */
	memset(&pktio_entry->s.pkt_mvgiu, 0, sizeof(pkt_mvgiu_t));

	/* Map GIU regfile */
	snprintf(file_name,
		 sizeof(file_name),
		 "%s%s%d", REGFILE_VAR_DIR, REGFILE_NAME_PREFIX, 0);

	/* Probe the GIU BPOOL */
	snprintf(name, sizeof(name), "giu_pool-%d:%d", giu_id, bpool_id);
	err = giu_bpool_probe(name, file_name,
			      &pktio_entry->s.pkt_mvgiu.bpool);
	if (err) {
		ODP_ERR("GIU BPool Probe failed (%d)\n", err);
		return -1;
	}

	err = giu_bpool_get_capabilities(pktio_entry->s.pkt_mvgiu.bpool,
					 &bpool_capa);
	if (err != 0) {
		ODP_ERR("giu_bpool_get_capabilities failed!\n");
		err = -1;
		goto fail;
	}

	/* Probe the GIU GPIO */
	snprintf(name, sizeof(name), "gpio-%d:%d", giu_id, gpio_id);
	err = giu_gpio_probe(name, file_name,
			     &pktio_entry->s.pkt_mvgiu.gpio);
	if (err) {
		ODP_ERR("GIU GPIO Init failed (%d)\n", err);
		return -1;
	}

	err = giu_gpio_get_capabilities(pktio_entry->s.pkt_mvgiu.gpio,
					&gpio_capa);
	if (err != 0) {
		ODP_ERR("giu_gpio_get_capabilities failed!\n");
		err = -1;
		goto fail;
	}

	pool_t *poole = pool_entry_from_hdl(pool);

	if (poole->data_size < bpool_capa.buff_len) {
		ODP_ERR("pool buffer's size is too small!\n");
		err = -1;
		goto fail;
	}

	/* Associate this pool with this pktio */
	pktio_entry->s.pkt_mvgiu.pool = pool;

	buf_num = MIN((poole->num / ODP_CONFIG_PKTIO_ENTRIES),
		      bpool_capa.max_num_buffs);

	/* Allocate maximum sized packets */
	/* Allocate 'buf_num' of the SW pool into the HW pool;
	 * i.e. allow only several ports sharing the same SW pool
	 */
	err = fill_bpool(pktio_entry->s.pkt_mvgiu.pool,
			 pktio_entry->s.pkt_mvgiu.bpool,
			 buf_num, bpool_capa.buff_len);
	if (err != 0) {
		ODP_ERR("can't fill port's pool with buffs!\n");
		err = -1;
		goto fail;
	}

	pktio_entry->s.pkt_mvgiu.mtu = MVPP2_DFLT_MTU;

	pktio_entry->s.pkt_mvgiu.inqs[0].first_tc = 0;
	pktio_entry->s.pkt_mvgiu.inqs[0].num_tcs = 1;
	pktio_entry->s.pkt_mvgiu.inqs[0].first_qid = 0;
	pktio_entry->s.pkt_mvgiu.inqs[0].next_qid = 0;
	pktio_entry->s.pkt_mvgiu.inqs[0].num_qids = 1;

	init_capability(pktio_entry);

	ODP_DBG("port '%s' is opened\n", devname);

fail:
	return err;
}

static int mvgiu_close(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	int tc = 0;
	struct mvgiu_tx_shadow_q *shadow_q;
	struct mvgiu_bufs_stockpile *bufs_stockpile;

	if (pktio_entry->s.pkt_mvgiu.gpio) {
		shadow_q = &pktio_entry->s.pkt_mvgiu.shadow_qs[tc];
		shadow_q->num_to_release = shadow_q->size;
		mvgiu_free_sent_buffers(shadow_q);
		bufs_stockpile =
			&pktio_entry->s.pkt_mvgiu.bufs_stockpile;
		if (bufs_stockpile->size)
			giu_bpool_put_buffs(pktio_entry->s.pkt_mvgiu.bpool,
					    bufs_stockpile->ent,
					    &bufs_stockpile->size);

		/* Deinit the GIU port */
		giu_gpio_remove(pktio_entry->s.pkt_mvgiu.gpio);
	}

	flush_bpool(pktio_entry->s.pkt_mvgiu.bpool);
	giu_bpool_remove(pktio_entry->s.pkt_mvgiu.bpool);

	ODP_DBG("port '%s' was closed\n", pktio_entry->s.name);
	return 0;

}

static int mvgiu_start(pktio_entry_t *pktio_entry)
{
	giu_gpio_enable(pktio_entry->s.pkt_mvgiu.gpio);

	ODP_PRINT("PktIO PP2 has %d RxTCs and %d TxTCs\n",
		  MVPP2_MAX_NUM_RX_TCS_PER_PORT,
		  MVPP2_MAX_NUM_TX_TCS_PER_PORT);
	ODP_PRINT("\t mapped to %d RxQs and %d TxQs!!!\n",
		  pktio_entry->s.num_in_queue, pktio_entry->s.num_out_queue);

	ODP_DBG("port '%s' is ready\n", pktio_entry->s.name);

	return 0;
}

static int mvgiu_stop(pktio_entry_t *pktio_entry)
{
	/* Set the GIU port in standby-mode.
	 * Ingress and egress disabled
	 */
	giu_gpio_disable(pktio_entry->s.pkt_mvgiu.gpio);
	ODP_DBG("port '%s' was stopped\n", pktio_entry->s.name);

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

static inline void parse(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
#ifdef MVGIU_SW_PARSE
	uint8_t			*data;
	const _odp_ethhdr_t	*eth;

	/* Need to perform SW parsing till HW support it */
	if (len > _ODP_ETH_LEN_MAX)
		pkt_hdr->p.input_flags.jumbo = 1;
	pkt_hdr->p.input_flags.l2 = 1;
	pkt_hdr->p.input_flags.eth = 1;
	pkt_hdr->p.l3_offset = sizeof(_odp_ethhdr_t);
	data = odp_packet_offset(packet_handle(pkt_hdr), 0, &len, NULL);
	eth = (const _odp_ethhdr_t *)data;

	/* For Ethernet II need to perform full parsing */
	if (odp_unlikely(odp_be_to_cpu_16(eth->type) > _ODP_ETH_LEN_MAX)) {
		packet_parse_reset(pkt_hdr);
		packet_parse_layer(pkt_hdr, ODP_PKTIO_PARSER_LAYER_ALL);
	}
#endif
}

inline void mvgiu_activate_free_sent_buffers(pktio_entry_t *pktio_entry)
{
	struct mvgiu_tx_shadow_q *shadow_q;
	pkt_mvgiu_t	*pkt_mvgiu = &pktio_entry->s.pkt_mvgiu;

	shadow_q = &pkt_mvgiu->shadow_qs[0];
	if (shadow_q->size)
		mvgiu_check_n_free_sent_buffers(pkt_mvgiu->gpio,
						shadow_q,
						0,
						0);
}

#ifdef ODP_MVNMP
static void nmp_scheduling(struct nmp *nmp)
{
	nmp_schedule(nmp, NMP_SCHED_MNG);
	nmp_schedule(nmp, NMP_SCHED_RX);
	nmp_schedule(nmp, NMP_SCHED_TX);
}
#endif /* ODP_MVNMP */

static int mvgiu_recv(pktio_entry_t *pktio_entry,
		      int rxq_id,
		      odp_packet_t pkt_table[],
		      int num_pkts)
{
	odp_packet_hdr_t	*pkt_hdr;
	odp_packet_t		pkt;
	pkt_mvgiu_t		*mvgiu = &pktio_entry->s.pkt_mvgiu;
	struct giu_gpio_desc	descs[MVGIU_MAX_RX_BURST_SIZE];
	u16			i, j, num, total_got, len;
	u8			tc, qid, num_qids, last_qid;
	u64			pkt_addr;
#ifdef MVGIU_SW_PARSE
#endif

	total_got = 0;
	if (num_pkts > (MVGIU_MAX_RX_BURST_SIZE * MVGIU_MAX_NUM_QS_PER_TC))
		num_pkts = MVGIU_MAX_RX_BURST_SIZE * MVGIU_MAX_NUM_QS_PER_TC;

	if (!mvgiu->inqs[rxq_id].lockless)
		odp_ticketlock_lock(&mvgiu->inqs[rxq_id].lock);

	tc = mvgiu->inqs[rxq_id].first_tc;
	qid = mvgiu->inqs[rxq_id].next_qid;
	num_qids = mvgiu->inqs[rxq_id].num_qids;
	last_qid = mvgiu->inqs[rxq_id].first_qid + num_qids - 1;
	for (i = 0; (i < num_qids) && (total_got != num_pkts); i++) {
		num = num_pkts - total_got;
		if (num > MVPP2_MAX_RX_BURST_SIZE)
			num = MVPP2_MAX_RX_BURST_SIZE;
#ifdef ODP_MVNMP
		nmp_schedule_all(nmp);
#endif /* ODP_MVNMP */
		giu_gpio_recv(mvgiu->gpio, tc, qid, descs, &num);
		for (j = 0; j < num; j++) {
			if ((num - j) > MVGIU_PREFETCH_SHIFT) {
				struct giu_gpio_desc *pref_desc;
				u64 pref_addr;
				odp_packet_hdr_t *pref_pkt_hdr;

				pref_desc = &descs[j + MVGIU_PREFETCH_SHIFT];
				pref_addr =
					giu_gpio_inq_desc_get_cookie(pref_desc);
				pref_addr |= sys_dma_high_addr;
				pref_pkt_hdr =
					odp_packet_hdr((odp_packet_t)pref_addr);
				odp_prefetch(pref_pkt_hdr);
				odp_prefetch(&pref_pkt_hdr->p);
			}

			pkt_addr = giu_gpio_inq_desc_get_cookie(&descs[j]) |
				sys_dma_high_addr;
			pkt_table[total_got] = (odp_packet_t)pkt_addr;
			len = giu_gpio_inq_desc_get_pkt_len(&descs[j]);

			pkt = pkt_table[total_got];
			pkt_hdr = odp_packet_hdr(pkt);

			packet_init(pkt_hdr, len);

			pkt_hdr->input = pktio_entry->s.handle;
			parse(pkt_hdr, len);
			total_got++;
		}
		if (odp_unlikely(qid++ == last_qid))
			qid = mvgiu->inqs[rxq_id].first_qid;
	}
	mvgiu->inqs[rxq_id].next_qid = qid;
	if (!mvgiu->inqs[rxq_id].lockless)
		odp_ticketlock_unlock(&mvgiu->inqs[rxq_id].lock);

	if (odp_unlikely(!total_got))
		activate_free_sent_buffers();

	return total_got;
}

static inline int
mrvl_prepare_proto_info(_odp_packet_input_flags_t packet_input_flags,
			enum giu_outq_l3_type *l3_type,
			enum giu_outq_l4_type *l4_type)
{
	if (packet_input_flags.ipv4)
		*l3_type = GIU_OUTQ_L3_TYPE_IPV4_NO_OPTS;
	else if (packet_input_flags.ipv6)
		*l3_type = GIU_OUTQ_L3_TYPE_IPV6_NO_EXT;
	else
		/* if something different then stop processing */
		return -1;

	if (packet_input_flags.tcp)
		*l4_type = GIU_OUTQ_L4_TYPE_TCP;
	else if (packet_input_flags.udp)
		*l4_type = GIU_OUTQ_L4_TYPE_UDP;
	else
		*l4_type = GIU_OUTQ_L4_TYPE_OTHER;

	return 0;
}

/* An implementation for enqueuing packets */
static int mvgiu_send(pktio_entry_t *pktio_entry,
		      int txq_id,
		      const odp_packet_t pkt_table[],
		      int num_pkts)
{
	odp_packet_t		pkt;
	odp_packet_hdr_t	*pkt_hdr;
	struct mvgiu_tx_shadow_q	*shadow_q;
	u16			shadow_q_free_size;
	struct giu_gpio_desc	descs[MVGIU_MAX_TX_BURST_SIZE];
	dma_addr_t		pa;
	u16			i, num, len, idx = 0;
	u8			tc;
	int			ret, sent = 0;
	pkt_mvgiu_t		*pkt_mvgiu = &pktio_entry->s.pkt_mvgiu;
	pktio_entry_t		*input_entry;
	enum giu_outq_l3_type	l3_type;
	enum giu_outq_l4_type	l4_type;

	tc = 0;
	txq_id = 0;

	shadow_q = &pkt_mvgiu->shadow_qs[tc];
	if (shadow_q->size)
		mvgiu_check_n_free_sent_buffers(pkt_mvgiu->gpio,
						shadow_q,
						tc,
						txq_id);

	shadow_q_free_size = SHADOW_Q_MAX_SIZE - shadow_q->size - 1;
	if (odp_unlikely(num_pkts > shadow_q_free_size)) {
		ODP_DBG("No room in shadow queue for %d packets!!!"
			"%d packets will be sent.\n",
			num_pkts, shadow_q_free_size);
		num_pkts = shadow_q_free_size;
	}

	for (i = 0; i < num_pkts; i++) {
		if ((num_pkts - i) > MVGIU_PREFETCH_SHIFT) {
			odp_packet_t pref_pkt;
			odp_packet_hdr_t *pref_pkt_hdr;

			pref_pkt = pkt_table[i + MVGIU_PREFETCH_SHIFT];
			pref_pkt_hdr = odp_packet_hdr(pref_pkt);
			odp_prefetch(pref_pkt_hdr);
			odp_prefetch(&pref_pkt_hdr->p);
		}

		pkt = pkt_table[i];
		len = odp_packet_len(pkt);
		if ((len - ODPH_ETHHDR_LEN) > pkt_mvgiu->mtu) {
			if (i == 0) {
				__odp_errno = EMSGSIZE;
				return -1;
			}
			break;
		}
		pkt_hdr = odp_packet_hdr(pkt);
		giu_gpio_outq_desc_reset(&descs[idx]);
#ifdef MVGIU_NO_HEADROOM
		pa = mv_sys_dma_mem_virt2phys(
			(void *)((uintptr_t)odp_packet_data(pkt)));
		giu_gpio_outq_desc_set_pkt_offset(&descs[idx], 0);
#else
		pa = mv_sys_dma_mem_virt2phys(
			(void *)((uintptr_t)odp_packet_head(pkt)));
		giu_gpio_outq_desc_set_pkt_offset(&descs[idx],
						  odp_packet_headroom(pkt));
#endif
		giu_gpio_outq_desc_set_pkt_len(&descs[idx], len);
		giu_gpio_outq_desc_set_phys_addr(&descs[idx], pa);

		/*
		 * in case unsupported input_flags were passed
		 * do not update descriptor offload information
		 */

		ret = mrvl_prepare_proto_info(pkt_hdr->p.input_flags,
					      &l3_type, &l4_type);
		if (odp_likely(!ret)) {
			giu_gpio_outq_desc_set_proto_info(&descs[idx],
							  l3_type,
							  l4_type,
							  pkt_hdr->p.l3_offset,
							  pkt_hdr->p.l4_offset);
		}

		shadow_q->ent[shadow_q->write_ind].addr = pa;
		shadow_q->ent[shadow_q->write_ind].cookie =
			(u64)(uintptr_t)pkt;

		input_entry = get_pktio_entry(pkt_hdr->input);
		if (odp_likely(input_entry &&
			       input_entry->s.ops == &mvgiu_pktio_ops)) {
			shadow_q->bpool[shadow_q->write_ind] =
				pkt_mvgiu->bpool;
			shadow_q->input_pktio[shadow_q->write_ind] =
				pkt_hdr->input;
		} else {
			shadow_q->bpool[shadow_q->write_ind] = NULL;
		}

		shadow_q->write_ind = (shadow_q->write_ind + 1) &
			SHADOW_Q_MAX_SIZE_MASK;
		shadow_q->size++;
		idx++;
		if (odp_unlikely(idx == MVGIU_MAX_TX_BURST_SIZE)) {
			num = idx;
			giu_gpio_send(pkt_mvgiu->gpio, tc, txq_id, descs, &num);
#ifdef ODP_MVNMP
			nmp_schedule_all(nmp);
#endif /* ODP_MVNMP */
			sent += num;
			/* In case not all frames were send we need to decrease
			 * the write_ind
			 */
			if (odp_unlikely(idx != num)) {
				idx -= num;
				shadow_q->write_ind =
						(SHADOW_Q_MAX_SIZE +
						shadow_q->write_ind - idx) &
						SHADOW_Q_MAX_SIZE_MASK;
				shadow_q->size -= idx;
				return sent;
			}
			idx = 0;
		}
	}
	num = idx;
	giu_gpio_send(pkt_mvgiu->gpio, tc, txq_id, descs, &num);
#ifdef ODP_MVNMP
	nmp_schedule_all(nmp);
#endif /* ODP_MVNMP */
	sent += num;

	/* In case not all frames were send we need to decrease the write_ind */
	if (odp_unlikely(idx != num)) {
		idx -= num;
		shadow_q->write_ind =
			(SHADOW_Q_MAX_SIZE + shadow_q->write_ind - idx) &
			SHADOW_Q_MAX_SIZE_MASK;
		shadow_q->size -= idx;
	}

	return sent;
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
