/* Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp_packet_io_internal.h>
#include <odp_packet_musdk.h>
#include <odp_debug_internal.h>
#include <protocols/eth.h>
#include <protocols/ip.h>
#include <protocols/tcp.h>
#include <protocols/udp.h>

/* prefetch=2, tested to be optimal both for
   mvgiu_recv() & mvgiu_send() prefetch operations */
#define MVGIU_PREFETCH_SHIFT		2
#define BUFFER_RELEASE_BURST_SIZE	64
#define MAX_BUFFER_GET_RETRIES		10000

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define MVGIU_NO_HEADROOM
#define MVGIU_SW_PARSE

static int mvgiu_free_buf(odp_buffer_t buf)
{
	odp_packet_t pkt = _odp_packet_from_buffer(buf);
	struct giu_buff_inf buff_inf;
	odp_packet_hdr_t *pkt_hdr;
	pktio_entry_t *pktio_entry;
	int err;

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
	buff_inf.cookie = (u64)pkt;
#ifdef MVGIU_NO_HEADROOM
	odp_packet_reset(pkt, pkt_hdr->frame_len);
	buff_inf.addr = mv_sys_dma_mem_virt2phys(odp_packet_data(pkt));
#else
	buff_inf.addr = mv_sys_dma_mem_virt2phys(odp_packet_head(pkt));
#endif

	err = giu_bpool_put_buff(pktio_entry->s.pkt_mvgiu.bpool, &buff_inf);
	return err;
}

static inline void mvgiu_free_sent_buffers(struct mvgiu_tx_shadow_q *shadow_q)
{
	struct mvgiu_buff_release_entry *entry;
	pktio_entry_t *pktio_entry;
	odp_packet_t pkt;
	u16 i, num_conf = 0;

	num_conf = shadow_q->num_to_release;
	shadow_q->num_to_release = 0;
	for (i = 0; i < num_conf; i++) {
		entry = &shadow_q->ent[shadow_q->read_ind];
		if (unlikely(!entry->buff.addr)) {
			ODP_ERR("Shadow memory @%d: cookie(%lx), pa(%lx)!\n",
				shadow_q->read_ind, (u64)entry->buff.cookie,
				(u64)entry->buff.addr);
			goto skip_buf;
		}

		if (unlikely(!entry->bpool)) {
			pkt = (odp_packet_t)((uintptr_t)entry->buff.cookie);
			odp_packet_free(pkt);
			goto skip_buf;
		}

		pktio_entry = get_pktio_entry(entry->input_pktio);
		if (unlikely(pktio_entry &&
			     pktio_entry->s.state == PKTIO_STATE_FREE)) {
			/* In case input pktio is in 'free' state, it means it
			 * was already closed and this buffer should be return
			 * to the ODP-POOL instead of the HW-Pool
			 */
			pkt = (odp_packet_t)((uintptr_t)entry->buff.cookie);
			odp_packet_hdr(pkt)->buf_hdr.ext_buf_free_cb = NULL;
			odp_packet_free(pkt);
			goto skip_buf;
		}

		giu_bpool_put_buff(entry->bpool, &entry->buff);
skip_buf:
		shadow_q->read_ind++;
		shadow_q->read_ind =
			shadow_q->read_ind & SHADOW_Q_MAX_SIZE_MASK;
		shadow_q->size--;
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
	int			 i, err = 0;
	odp_packet_hdr_t	*pkt_hdr;
	odp_packet_t		 pkt;
	struct giu_buff_inf	 buff_inf;

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
			ODP_ERR("pkt(%p) ext_buf_free_cb was set; skipping\n",
				pkt);
			continue;
		}
		pkt_hdr->buf_hdr.ext_buf_free_cb = mvgiu_free_buf;

		buff_inf.cookie = (u64)pkt;
#ifdef MVGIU_NO_HEADROOM
		buff_inf.addr = mv_sys_dma_mem_virt2phys(odp_packet_data(pkt));
#else
		buff_inf.addr = mv_sys_dma_mem_virt2phys(odp_packet_head(pkt));
#endif
		err = giu_bpool_put_buff(bpool, &buff_inf);

		if (err != 0)
			return err;
	}

	return 0;
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
		pkt = (odp_packet_t)buff.cookie;
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

	if (pktio_entry->s.pkt_mvgiu.gpio) {
		shadow_q = &pktio_entry->s.pkt_mvgiu.shadow_qs[tc];
		shadow_q->num_to_release = shadow_q->size;
		mvgiu_free_sent_buffers(shadow_q);

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

static int mvgiu_recv(pktio_entry_t *pktio_entry,
		      int rxq_id,
		      odp_packet_t pkt_table[],
		      int num_pkts)
{
	odp_packet_hdr_t	*pkt_hdr;
	odp_packet_t		pkt;
	pkt_mvgiu_t		*pkt_mvgiu = &pktio_entry->s.pkt_mvgiu;
	struct giu_gpio_desc	descs[MVGIU_MAX_RX_BURST_SIZE];
	u16			i, j, num, total_got, len;
	u8			tc, qid, num_qids, last_qid;
	int			err;
#ifdef MVGIU_SW_PARSE
#endif

	total_got = 0;
	if (num_pkts > (MVGIU_MAX_RX_BURST_SIZE * MVGIU_MAX_NUM_QS_PER_TC))
		num_pkts = MVGIU_MAX_RX_BURST_SIZE * MVGIU_MAX_NUM_QS_PER_TC;

	if (!pkt_mvgiu->inqs[rxq_id].lockless)
		odp_ticketlock_lock(&pkt_mvgiu->inqs[rxq_id].lock);

	tc = pkt_mvgiu->inqs[rxq_id].first_tc;
	qid = pkt_mvgiu->inqs[rxq_id].next_qid;
	num_qids = pkt_mvgiu->inqs[rxq_id].num_qids;
	last_qid = pkt_mvgiu->inqs[rxq_id].first_qid + num_qids - 1;
	for (i = 0; (i < num_qids) && (total_got != num_pkts); i++) {
		num = num_pkts - total_got;
		if (num > MVPP2_MAX_RX_BURST_SIZE)
			num = MVPP2_MAX_RX_BURST_SIZE;
#ifdef ODP_MVNMP
		nmp_schedule();
#endif /* ODP_MVNMP */
		giu_gpio_recv(pkt_mvgiu->gpio, tc, qid, descs, &num);
		for (j = 0; j < num; j++) {
			if ((num - j) > MVGIU_PREFETCH_SHIFT) {
				struct giu_gpio_desc *pref_desc;
				u64 pref_addr;
				odp_packet_hdr_t *pref_pkt_hdr;

				pref_desc = &descs[j + MVGIU_PREFETCH_SHIFT];
				pref_addr =
					giu_gpio_inq_desc_get_cookie(pref_desc);
				pref_pkt_hdr =
					odp_packet_hdr((odp_packet_t)pref_addr);
				odp_prefetch(pref_pkt_hdr);
				odp_prefetch(&pref_pkt_hdr->p);
			}

			pkt_table[total_got] = (odp_packet_t)
				giu_gpio_inq_desc_get_cookie(&descs[j]);
			len = giu_gpio_inq_desc_get_pkt_len(&descs[j]);

			pkt = pkt_table[total_got];
			pkt_hdr = odp_packet_hdr(pkt);

			packet_init(pkt_hdr, len);

			pkt_hdr->input = pktio_entry->s.handle;
			parse(pkt_hdr, len);
			total_got++;
		}
		if (odp_unlikely(qid++ == last_qid))
			qid = pkt_mvgiu->inqs[rxq_id].first_qid;
	}
	pkt_mvgiu->inqs[rxq_id].next_qid = qid;
	if (!pkt_mvgiu->inqs[rxq_id].lockless)
		odp_ticketlock_unlock(&pkt_mvgiu->inqs[rxq_id].lock);

	return total_got;
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
	int			sent = 0;
	pkt_mvgiu_t		*pkt_mvgiu = &pktio_entry->s.pkt_mvgiu;
	pktio_entry_t		*input_entry;

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
		shadow_q->ent[shadow_q->write_ind].buff.addr = pa;
		shadow_q->ent[shadow_q->write_ind].buff.cookie =
			(u64)(uintptr_t)pkt;

		input_entry = get_pktio_entry(pkt_hdr->input);
		if (odp_likely(input_entry &&
			       input_entry->s.ops == &mvgiu_pktio_ops)) {
			shadow_q->ent[shadow_q->write_ind].bpool =
				pkt_mvgiu->bpool;
			shadow_q->ent[shadow_q->write_ind].input_pktio =
				pkt_hdr->input;
		} else {
			shadow_q->ent[shadow_q->write_ind].bpool = NULL;
		}

		shadow_q->write_ind = (shadow_q->write_ind + 1) &
			SHADOW_Q_MAX_SIZE_MASK;
		shadow_q->size++;
		idx++;
		if (odp_unlikely(idx == MVGIU_MAX_TX_BURST_SIZE)) {
			num = idx;
			giu_gpio_send(pkt_mvgiu->gpio, tc, txq_id, descs, &num);
#ifdef ODP_MVNMP
			nmp_schedule();
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
	nmp_schedule();
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
