/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_MUSDK_H_
#define ODP_PACKET_MUSDK_H_

#include <odp_align_internal.h>
#include <odp_config_internal.h>
#include <odp/api/ticketlock.h>
#include <odp/helper/eth.h>

#include <drivers/mv_pp2_bpool.h>
#include <drivers/mv_pp2_ppio.h>
#include <drivers/mv_pp2_cls.h>
#ifdef ODP_PKTIO_MVGIU
#include <drivers/mv_giu_bpool.h>
#include <drivers/mv_giu_gpio.h>
#endif /* ODP_PKTIO_MVGIU */
#if defined(ODP_MVNMP) || defined(ODP_MVNMP_GUEST_MODE)
#include <mng/mv_nmp.h>
#include <fcntl.h>
#endif /* defined(ODP_MVNMP) || defined(ODP_MVNMP_GUEST_MODE) */

#define MAX_NUM_OUTQS_PER_CORE	MVPP2_MAX_NUM_TX_TCS_PER_PORT
#define SHADOW_Q_MAX_SIZE	MVPP2_TXQ_SIZE	/* Should be power of 2 */
#define SHADOW_Q_MAX_SIZE_MASK	(SHADOW_Q_MAX_SIZE - 1)

ODP_STATIC_ASSERT((CHECK_IS_POWER2(SHADOW_Q_MAX_SIZE)), \
	"SHADOW_Q_MAX_SIZE should be power of 2");

#if defined(ODP_MVNMP) || defined(ODP_MVNMP_GUEST_MODE)
#define REGFILE_VAR_DIR         "/var/"
#define REGFILE_NAME_PREFIX     "nic-pf-"
#define REGFILE_MAX_FILE_NAME   64
#endif /* defined(ODP_MVNMP) || defined(ODP_MVNMP_GUEST_MODE) */

struct mvpp2_tx_shadow_q {
	/* read index - used when releasing buffers */
	u16				read_ind;
	/* write index - used when sending buffers */
	u16				write_ind;
	/* queue occupied size */
	u16				size;
	/* number of buffers sent, that can be released */
	u16				num_to_release;
	/* queue entries */
	struct buff_release_entry	ent[SHADOW_Q_MAX_SIZE];
	/* input-pktio for each buff-entry; the queue-entries MUST be of type
	 * 'buff_release_entry' as there is an assumption it is continuous
	 * when it is used in 'pp2_bpool_put_buffs'
	 */
	odp_pktio_t			input_pktio[SHADOW_Q_MAX_SIZE];
};

#ifdef ODP_PKTIO_MVGIU
struct mvgiu_buff_release_entry {
	struct giu_buff_inf	buff;	/* pointer to the buffer object */
	struct giu_bpool	*bpool;	/* pointer to the bpool object */
	odp_pktio_t		input_pktio;
};

struct mvgiu_tx_shadow_q {
	/* read index - used when releasing buffers */
	u16			read_ind;
	/* write index - used when sending buffers */
	u16			write_ind;
	/* queue occupied size */
	u16			size;
	/* number of buffers sent, that can be released */
	u16			num_to_release;
	/* queue entries */
	struct mvgiu_buff_release_entry	ent[SHADOW_Q_MAX_SIZE];
};
#endif /* ODP_PKTIO_MVGIU */

struct inq_info {
	u8			 first_tc;
	u8			 num_tcs;
	u8			 first_qid;
	u8			 next_qid;
	u8			 num_qids;
	int			 lockless;
	odp_ticketlock_t	 lock;  /**< Queue lock */
};

typedef struct {
	uint16_t		pp_id;
	uint16_t		ppio_id;
	uint16_t		bpool_id;
	uint16_t		mtu;

	/* MVPP2 PP-IO handle */
	struct pp2_ppio		*ppio;
	/* MVPP2 BM Pool handle */
	struct pp2_bpool	*bpool;
	/**< pool to alloc packets from */
	odp_pool_t		pool;
	/**< eth mac address */
	u8			if_mac[ODPH_ETHADDR_LEN];
	int			sockfd;
	odp_pktio_capability_t	capa;	/**< interface capabilities */
	int			num_out_queues;
	struct mvpp2_tx_shadow_q
		shadow_qs[MVPP2_TOTAL_NUM_HIFS][MAX_NUM_OUTQS_PER_CORE];
	u8			num_inqs;
	struct inq_info		inqs[MVPP2_MAX_NUM_RX_QS_PER_PORT];
	enum pp2_ppio_hash_type	hash_type;
	struct pp2_cls_qos_tbl_params qos_tbl_params;
	struct pp2_cls_tbl *qos_tbl;
	odp_ticketlock_t l2_l3_cos_lock;
} pkt_mvpp2_t;

#ifdef ODP_PKTIO_MVGIU
typedef struct {
	uint16_t		gpio_id;
	uint16_t		bpool_id;
	uint16_t		mtu;

	/* MVPP2 PP-IO handle */
	struct giu_gpio		*gpio;
	/* MVGIU BM Pool handle */
	struct giu_bpool	*bpool;
	odp_pool_t		pool;	/**< pool to alloc packets from */
	odp_pktio_capability_t	capa;	/**< interface capabilities */
	struct mvgiu_tx_shadow_q
		shadow_qs[MAX_NUM_OUTQS_PER_CORE];
	struct inq_info	inqs[MVGIU_MAX_NUM_QS_PER_TC];
} pkt_mvgiu_t;
#endif /* ODP_PKTIO_MVGIU */

void mvpp2_init_cls(odp_pktio_t pktio);
void mvpp2_deinit_cls(odp_pktio_t pktio);
int mvpp2_update_qos(odp_pktio_t pktio);
int mvpp2_cls_select_cos(odp_pktio_t pktio,
			 odp_packet_t *pkt,
			 int hw_rxq_id);

#endif /* ODP_PACKET_MUSDK_H_ */
