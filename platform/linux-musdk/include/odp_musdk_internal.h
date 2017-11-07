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

#endif /* ODP_MUSDK_INTERNAL_H_ */
