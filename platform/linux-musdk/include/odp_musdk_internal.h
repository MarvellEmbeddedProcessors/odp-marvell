/* Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_MUSDK_INTERNAL_H_
#define ODP_MUSDK_INTERNAL_H_

#include <odp_packet_io_internal.h>

void mvpp2_init_cls(pktio_entry_t *pktio_entry);
void mvpp2_deinit_cls(pktio_entry_t *pktio_entry);
int mvpp2_update_qos(pktio_entry_t *pktio_entry);
int mvpp2_cls_select_cos(pktio_entry_t *pktio_entry,
			 odp_packet_t *pkt,
			 int hw_rxq_id);

void mvpp2_activate_free_sent_buffers(pktio_entry_t *pktio_entry);
#ifdef ODP_PKTIO_MVGIU
void mvgiu_activate_free_sent_buffers(pktio_entry_t *pktio_entry);
#endif /* ODP_PKTIO_MVGIU */

extern pktio_table_t *pktio_tbl;

static inline void activate_free_sent_buffers(void)
{
	pktio_entry_t	*pktio_entry;
	int i;

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		pktio_entry = &pktio_tbl->entries[i];

		if (!pktio_entry ||
		    (pktio_entry->s.state == PKTIO_STATE_FREE))
			continue;

		if (pktio_entry->s.ops == &mvpp2_pktio_ops)
			mvpp2_activate_free_sent_buffers(pktio_entry);
#ifdef ODP_PKTIO_MVGIU
		if (pktio_entry->s.ops == &mvgiu_pktio_ops)
			mvgiu_activate_free_sent_buffers(pktio_entry);
#endif /* ODP_PKTIO_MVGIU */
	}
}

#endif /* ODP_MUSDK_INTERNAL_H_ */
