/* Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_CONFIG_INTERNAL_H_
#define ODP_CONFIG_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/* MUSDK - start */
/* TODO: MUSDK: get rid of the following lines and make them generic. */
#define MVPP2_TOTAL_NUM_HIFS	9
#define MVPP2_TOTAL_NUM_BPOOLS	16

#define MVPP2_BUFFER_OFFSET	0
#define MVPP2_PACKET_OFFSET	64
#define MVPP2_MH_SIZE		2
#define MVPP2_HIF_RSRV		0xF
#define MVPP2_BPOOL_RSRV	0x7

#define MVPP2_MAX_NUM_TCS_PER_PORT	1
/* TODO: temporary set num-RxQs-per-tc according to #cores */
#define MVPP2_MAX_NUM_QS_PER_TC		4
#define MVPP2_RXQ_SIZE			512
#define MVPP2_TXQ_SIZE			2048
#define MVPP2_DFLT_MTU			1500

#define MVPP2_PKT_PARSE_SUPPORT	1
#define MVPP2_CSUM_OFF_SUPPORT	0

#define MVSAM_TOTAL_NUM_CIOS	4

/* TODO: reserve some rings for the LK */
#define MVSAM_CIOS_RSRV		0x0
#define MVSAM_RING_SIZE		256
#define MVSAM_MAX_NUM_SESSIONS_PER_RING	2
#define MVSAM_MULTI_SAM_ASYMMETRIC_MODE

#define MUSDK_TOTAL_SHM_SIZE		(48 * 1024 * 1024)
/* MUSDK - end */

#define ODP_CONFIG_PKTIO_PKT_PARSE_SUPPORT	MVPP2_PKT_PARSE_SUPPORT
#define ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT	MVPP2_CSUM_OFF_SUPPORT

/*
 * Maximum number of pools
 */
#define ODP_CONFIG_POOLS 4

/*
 * Maximum number of queues
 */
#define ODP_CONFIG_QUEUES 1024

/*
 * Maximum number of packet IO resources
 */
#define ODP_CONFIG_PKTIO_ENTRIES 4

/*
 * Minimum buffer alignment
 *
 * This defines the minimum supported buffer alignment. Requests for values
 * below this will be rounded up to this value.
 */
#define ODP_CONFIG_BUFFER_ALIGN_MIN 64

/*
 * Maximum buffer alignment
 *
 * This defines the maximum supported buffer alignment. Requests for values
 * above this will fail.
 */
#define ODP_CONFIG_BUFFER_ALIGN_MAX (4 * 1024)

/*
 * Offset relative to the beginning of data, is used internally by hardware.
 */
#define ODP_CONFIG_BUFFER_OFFSET    (MVPP2_BUFFER_OFFSET)

/*
 * Default packet headroom
 *
 * This defines the minimum number of headroom bytes that newly created packets
 * have by default. The default apply to both ODP packet input and user
 * allocated packets. Implementations may reserve a larger than minimum headroom
 * size e.g. due to HW or a protocol specific alignment requirement.
 *
 * @internal In odp-linux implementation:
 * The default value (66) allows a 1500-byte packet to be received into a single
 * segment with Ethernet offset alignment and room for some header expansion.
 *      -------------------------------------------------------------------------
 * HW:  | PacketOffset(32B*N, N>=1)             |Marvell Header(2B)| data       |
 *      -------------------------------------------------------------------------
 *
 *      -------------------------------------------------------------------------
 * ODP: |32B(HW buffer offset) | headroom size                     | data       |
 *      -------------------------------------------------------------------------
 */
#define ODP_CONFIG_PACKET_HEADROOM ((MVPP2_PACKET_OFFSET) + (MVPP2_MH_SIZE) - ODP_CONFIG_BUFFER_OFFSET)

/*
 * Default packet tailroom
 *
 * This defines the minimum number of tailroom bytes that newly created packets
 * have by default. The default apply to both ODP packet input and user
 * allocated packets. Implementations are free to add to this as desired
 * without restriction. Note that most implementations will automatically
 * consider any unused portion of the last segment of a packet as tailroom
 */
#define ODP_CONFIG_PACKET_TAILROOM 0

/*
 * Maximum number of segments per packet
 */
#define ODP_CONFIG_PACKET_MAX_SEGS 6

/*
 * Minimum packet segment length
 *
 * This defines the minimum packet segment buffer length in bytes. The user
 * defined segment length (seg_len in odp_pool_param_t) will be rounded up into
 * this value.
 */
#define ODP_CONFIG_PACKET_SEG_LEN_MIN (MVPP2_DFLT_MTU + ODP_CONFIG_PACKET_HEADROOM + ODP_CONFIG_PACKET_TAILROOM)

/*
 * Maximum packet segment length
 *
 * This defines the maximum packet segment buffer length in bytes. The user
 * defined segment length (seg_len in odp_pool_param_t) must not be larger than
 * this.
 */
#define ODP_CONFIG_PACKET_SEG_LEN_MAX (64 * 1024)

/*
 * Maximum packet buffer length
 *
 * This defines the maximum number of bytes that can be stored into a packet
 * (maximum return value of odp_packet_buf_len(void)). Attempts to allocate
 * (including default head- and tailrooms) or extend packets to sizes larger
 * than this limit will fail.
 *
 * @internal In odp-linux implementation:
 * - The value MUST be an integral number of segments
 * - The value SHOULD be large enough to accommodate jumbo packets (9K)
 */
#define ODP_CONFIG_PACKET_BUF_LEN_MAX (ODP_CONFIG_PACKET_SEG_LEN_MIN * 6)

/* Maximum number of shared memory blocks.
 *
 * This the the number of separate SHM areas that can be reserved concurrently
 */
#define ODP_CONFIG_SHM_BLOCKS (ODP_CONFIG_POOLS + 48)

/*
 * Maximum event burst size
 *
 * This controls the burst size on various enqueue, dequeue, etc calls. Large
 * burst size improves throughput, but may degrade QoS (increase latency).
 */
#define CONFIG_BURST_SIZE 256

#ifdef __cplusplus
}
#endif

#endif
