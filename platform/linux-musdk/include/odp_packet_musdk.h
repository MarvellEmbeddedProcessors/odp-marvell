/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_MUSDK_H_
#define ODP_PACKET_MUSDK_H_

#include <drivers/mv_pp2_bpool.h>
#include <drivers/mv_pp2_ppio.h>

#define MAX_NUM_QS_PER_CORE		MVPP2_MAX_NUM_TCS_PER_PORT

typedef struct {
	uint16_t		 pp_id;
	uint16_t		 ppio_id;
	uint16_t		 bpool_id;
	uint16_t		 mtu;

	/* MVPP2 PP-IO handle */
	struct pp2_ppio		*ppio;
	/* MVPP2 BM Pool handle */
	struct pp2_bpool	*bpool;
	odp_pool_t		 pool;			/**< pool to alloc packets from */

	unsigned char		 if_mac[ETH_ALEN];	/**< eth mac address */
	int			 sockfd;
	odp_pktio_capability_t	 capa;	/**< interface capabilities */
} pkt_mvpp2_t;

#endif /* ODP_PACKET_MUSDK_H_ */
