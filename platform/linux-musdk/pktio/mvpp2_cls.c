/* Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#include <odp_posix_extensions.h>
#include <odp_packet_io_internal.h>

#include <odp/api/plat/ticketlock_inlines.h>
#define LOCK(a)      _odp_ticketlock_lock(a)
#define UNLOCK(a)    _odp_ticketlock_unlock(a)
#define LOCK_INIT(a) odp_ticketlock_init(a)

int mvpp2_cos_with_l2_priority(pktio_entry_t *entry,
			       uint8_t num_qos,
			       uint8_t qos_table[]);
int mvpp2_cos_with_l3_priority(pktio_entry_t *entry,
			       uint8_t num_qos,
			       uint8_t qos_table[]);

static inline cos_t *get_l3_cos(pktio_entry_t *pktio_entry,
				odp_packet_hdr_t *pkt_hdr,
				int hw_rxq_id)
{
	pmr_l3_cos_t *l3_cos = &pktio_entry->s.cls.l3_cos_table;

	if (pkt_hdr->p.input_flags.l3 &&
	    (pkt_hdr->p.input_flags.ipv4 || pkt_hdr->p.input_flags.ipv6))
		return l3_cos->cos_by_idx[hw_rxq_id - MVPP2_CLS_COS0_HWQ];
	return NULL;
}

static inline cos_t *get_l2_cos(pktio_entry_t *pktio_entry,
				odp_packet_hdr_t *pkt_hdr,
				int hw_rxq_id)
{
	pmr_l2_cos_t *l2_cos = &pktio_entry->s.cls.l2_cos_table;

	if (pkt_hdr->p.input_flags.l2 &&
	    (pkt_hdr->p.input_flags.vlan || pkt_hdr->p.input_flags.vlan_qinq))
		return l2_cos->cos_by_idx[hw_rxq_id - MVPP2_CLS_COS0_HWQ];
	return NULL;
}

static inline cos_t *get_l2_l3_cos(pktio_entry_t *pktio_entry,
				   odp_packet_hdr_t *pkt_hdr,
				   int hw_rxq_id)
{
	cos_t *cos = NULL;

	if (pktio_entry->s.cls.l3_precedence) {
		cos = get_l3_cos(pktio_entry, pkt_hdr, hw_rxq_id);
		if (cos)
			return cos;
		cos = get_l2_cos(pktio_entry, pkt_hdr, hw_rxq_id);
	} else {
		cos = get_l2_cos(pktio_entry, pkt_hdr, hw_rxq_id);
		if (cos)
			return cos;
		cos = get_l3_cos(pktio_entry, pkt_hdr, hw_rxq_id);
	}

	return cos;
}

static cos_t *get_cos(pktio_entry_t *pktio_entry,
		      odp_packet_hdr_t *pkt_hdr,
		      int hw_rxq_id)
{
	cos_t *cos = NULL;

	/**
	 * Decode CoS based on hardware queue indexed entries set by classifier.
	 * Parameter 'hw_rxq_id' has to be set to RECV_ERROR_QUEUE when an error
	 * is signaled by Ethernet controller in order to decode error
	 * CoS ODP queue */
	if (MVPP2_DEFAULT_HWQ == hw_rxq_id)
		/* Default CoS handling */
		cos = pktio_entry->s.cls.default_cos;
	else if (MVPP2_RECV_ERROR_QUEUE == hw_rxq_id)
		/* Error CoS handling */
		cos = pktio_entry->s.cls.error_cos;
	else
		cos = get_l2_l3_cos(pktio_entry, pkt_hdr, hw_rxq_id);

	return cos;
}

void mvpp2_init_cls(odp_pktio_t pktio)
{
	pktio_entry_t *entry = get_pktio_entry(pktio);
	uint32_t i;

	LOCK_INIT(&entry->s.pkt_mvpp2.l2_l3_cos_lock);
	/* Update QoS table parameters with PPIO handle */
	for (i = 0; i < MV_VLAN_PRIO_NUM; i++)
		entry->s.pkt_mvpp2.qos_tbl_params.pcp_cos_map[i].ppio =
			entry->s.pkt_mvpp2.ppio;

	for (i = 0; i < MV_DSCP_NUM; i++)
		entry->s.pkt_mvpp2.qos_tbl_params.dscp_cos_map[i].ppio =
			entry->s.pkt_mvpp2.ppio;
}

void mvpp2_deinit_cls(odp_pktio_t pktio)
{
	pktio_entry_t *entry = get_pktio_entry(pktio);

	if (!entry->s.pkt_mvpp2.ppio)
		return;

	if (entry->s.pkt_mvpp2.qos_tbl)
		pp2_cls_qos_tbl_deinit(entry->s.pkt_mvpp2.qos_tbl);
}

int mvpp2_update_qos(odp_pktio_t pktio)
{
	pktio_entry_t *entry = get_pktio_entry(pktio);

	if (!entry->s.pkt_mvpp2.ppio)
		return 0;

	if (entry->s.pkt_mvpp2.qos_tbl)
		pp2_cls_qos_tbl_deinit(entry->s.pkt_mvpp2.qos_tbl);

	if ((entry->s.pkt_mvpp2.qos_tbl_params.type != PP2_CLS_QOS_TBL_NONE) &&
	    (pp2_cls_qos_tbl_init(&entry->s.pkt_mvpp2.qos_tbl_params,
				  &entry->s.pkt_mvpp2.qos_tbl) != 0))
		return -1;
	return 0;
}

inline int mvpp2_cls_select_cos(odp_pktio_t pktio,
				odp_packet_t *pkt,
				int hw_rxq_id)
{
	odp_queue_t queue = ODP_QUEUE_INVALID;
	odp_pool_t pool = ODP_POOL_INVALID;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(*pkt);
	odp_packet_t new_pkt;
	cos_t *cos = NULL;
	pktio_entry_t *entry = get_pktio_entry(pktio);

	if (pkt_hdr->p.error_flags.all)
		cos = get_cos(entry, pkt_hdr, MVPP2_RECV_ERROR_QUEUE);
	else
		cos = get_cos(entry, pkt_hdr, hw_rxq_id);

	if (cos) {
		pool = cos->s.pool;
		queue = cos->s.queue->s.handle;
	}

	if ((pool != ODP_POOL_INVALID) &&
	    (pool != odp_packet_pool(*pkt))) {
		/* The user has asked to use other pool	for this CoS
		 * We have to allocate from this pool and copy data.
		 */

		new_pkt = odp_packet_copy(*pkt, pool);
		odp_packet_free(*pkt);

		if (new_pkt == ODP_PACKET_INVALID)
			return -1;
		*pkt = new_pkt;
		pkt_hdr = odp_packet_hdr(new_pkt);
	}

	if (queue != ODP_QUEUE_INVALID) {
		pkt_hdr->p.input_flags.dst_queue = 1;
		pkt_hdr->dst_queue = queue;
	}

	return 0;
}

int mvpp2_cos_with_l2_priority(pktio_entry_t *entry,
			       uint8_t num_qos,
			       uint8_t qos_table[])
{
	struct pp2_cls_qos_tbl_params *qos_tbl_params;
	uint32_t i;
	int ret;

	LOCK(&entry->s.pkt_mvpp2.l2_l3_cos_lock);
	/** QoS according to VLAN-priority (outer tag) if exists;
	 * otherwise, use default */
	qos_tbl_params = &entry->s.pkt_mvpp2.qos_tbl_params;
	if (qos_tbl_params->type <= PP2_CLS_QOS_TBL_VLAN_PRI)
		qos_tbl_params->type = PP2_CLS_QOS_TBL_VLAN_PRI;

	/* fill pcp_table with l2 prio values, if any */
	for (i = 0; i < ODP_COS_MAX_L2_QOS; i++)
		qos_tbl_params->pcp_cos_map[i].tc = MVPP2_DEFAULT_HWQ;
	for (i = 0; i < num_qos; i++)
		if (qos_table[i] < ODP_COS_MAX_L2_QOS)
			qos_tbl_params->pcp_cos_map[qos_table[i]].tc =
				MVPP2_CLS_COS0_HWQ + i;

	ret = mvpp2_update_qos(entry->s.handle);
	UNLOCK(&entry->s.pkt_mvpp2.l2_l3_cos_lock);
	if (ret != 0)
		return -1;

	return 0;
}

int mvpp2_cos_with_l3_priority(pktio_entry_t *entry,
			       uint8_t num_qos,
			       uint8_t qos_table[])
{
	struct pp2_cls_qos_tbl_params *qos_tbl_params;
	uint32_t i;
	int ret;

	LOCK(&entry->s.pkt_mvpp2.l2_l3_cos_lock);
	qos_tbl_params = &entry->s.pkt_mvpp2.qos_tbl_params;
	qos_tbl_params->type = entry->s.cls.l3_precedence
			? PP2_CLS_QOS_TBL_IP_VLAN_PRI
			: PP2_CLS_QOS_TBL_VLAN_IP_PRI;

	/* fill dscp_table with L3 prio values, if any */
	for (i = 0; i < ODP_COS_MAX_L3_QOS; i++)
		qos_tbl_params->dscp_cos_map[i].tc = MVPP2_DEFAULT_HWQ;
	for (i = 0; i < num_qos; i++)
		if (qos_table[i] < ODP_COS_MAX_L3_QOS)
			qos_tbl_params->dscp_cos_map[qos_table[i]].tc =
				MVPP2_CLS_COS0_HWQ + i;

	ret = mvpp2_update_qos(entry->s.handle);
	UNLOCK(&entry->s.pkt_mvpp2.l2_l3_cos_lock);
	if (ret != 0)
		return -1;

	return 0;
}

