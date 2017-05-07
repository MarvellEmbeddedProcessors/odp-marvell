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

#define MAX_NUM_OUTQS_PER_CORE		MVPP2_MAX_NUM_TCS_PER_PORT
#define SHADOW_Q_MAX_SIZE		MVPP2_TXQ_SIZE		/* Should be power of 2 */
#define SHADOW_Q_MAX_SIZE_MASK		(SHADOW_Q_MAX_SIZE - 1)

ODP_STATIC_ASSERT((ODP_VAL_IS_POWER_2(SHADOW_Q_MAX_SIZE)), "SHADOW_Q_MAX_SIZE should be power of 2");

struct tx_shadow_q {
	u16				 read_ind;		/* read index - used when releasing buffers */
	u16				 write_ind;		/* write index - used when sending buffers */
	u16				 size;			/* queue occupied size */
	u16				 num_to_release;	/* number of buffers sent, that can be released */
	struct buff_release_entry	 ent[SHADOW_Q_MAX_SIZE];/* queue entries */
};

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
	struct tx_shadow_q	 shadow_qs[MVPP2_TOTAL_NUM_HIFS][MAX_NUM_OUTQS_PER_CORE];
} pkt_mvpp2_t;

#endif /* ODP_PACKET_MUSDK_H_ */
