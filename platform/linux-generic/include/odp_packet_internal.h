/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet descriptor - implementation internal
 */

#ifndef ODP_PACKET_INTERNAL_H_
#define ODP_PACKET_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/api/debug.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_buffer_inlines.h>
#include <odp/api/packet.h>
#include <odp/api/packet_io.h>
#include <odp/api/crypto.h>
#include <odp_crypto_internal.h>
#include <odp/api/plat/packet_types.h>

/** Minimum segment length expected by packet_parse_common() */
#define PACKET_PARSE_SEG_LEN 96


ODP_STATIC_ASSERT(sizeof(_odp_packet_input_flags_t) == sizeof(uint64_t),
		  "INPUT_FLAGS_SIZE_ERROR");

/**
 * Packet error flags
 */
typedef union {
	/* All error flags */
	uint32_t all;

	struct {
		/* Bitfield flags for each detected error */
		uint32_t app_error:1; /**< Error bit for application use */
		uint32_t frame_len:1; /**< Frame length error */
		uint32_t snap_len:1;  /**< Snap length error */
		uint32_t l2_chksum:1; /**< L2 checksum error, checks TBD */
		uint32_t ip_err:1;    /**< IP error,  checks TBD */
		uint32_t tcp_err:1;   /**< TCP error, checks TBD */
		uint32_t udp_err:1;   /**< UDP error, checks TBD */
	};
} error_flags_t;

ODP_STATIC_ASSERT(sizeof(error_flags_t) == sizeof(uint32_t),
		  "ERROR_FLAGS_SIZE_ERROR");

/**
 * Packet output flags
 */
typedef union {
	/* All output flags */
	uint32_t all;

	struct {
		/** adjustment for traffic mgr */
		uint32_t shaper_len_adj:8;

		/* Bitfield flags for each output option */
		uint32_t l3_chksum_set:1; /**< L3 chksum bit is valid */
		uint32_t l3_chksum:1;     /**< L3 chksum override */
		uint32_t l4_chksum_set:1; /**< L3 chksum bit is valid */
		uint32_t l4_chksum:1;     /**< L4 chksum override  */
	};
} output_flags_t;

ODP_STATIC_ASSERT(sizeof(output_flags_t) == sizeof(uint32_t),
		  "OUTPUT_FLAGS_SIZE_ERROR");

/**
 * Packet parser metadata
 */
typedef struct {
	_odp_packet_input_flags_t  input_flags;
	error_flags_t  error_flags;
	output_flags_t output_flags;

	uint32_t l2_offset; /**< offset to L2 hdr, e.g. Eth */
	uint32_t l3_offset; /**< offset to L3 hdr, e.g. IPv4, IPv6 */
	uint32_t l4_offset; /**< offset to L4 hdr (TCP, UDP, SCTP, also ICMP) */
} packet_parser_t;

/**
 * Internal Packet header
 *
 * To optimize fast path performance this struct is not initialized to zero in
 * packet_init(). Because of this any new fields added must be reviewed for
 * initialization requirements.
 */
typedef struct {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;

	/*
	 * Following members are initialized by packet_init()
	 */

	packet_parser_t p;

	odp_pktio_t input;

	uint32_t frame_len;
	uint32_t headroom;
	uint32_t tailroom;

	/*
	 * Members below are not initialized by packet_init()
	 */

	/* Flow hash value */
	uint32_t flow_hash;

	/* Timestamp value */
	odp_time_t timestamp;

	/* Classifier destination queue */
	odp_queue_t dst_queue;

	/* Result for crypto */
	odp_crypto_generic_op_result_t op_result;

	/* Packet data storage */
	uint8_t data[0];
} odp_packet_hdr_t;

/**
 * Return the packet header
 */
static inline odp_packet_hdr_t *odp_packet_hdr(odp_packet_t pkt)
{
	return (odp_packet_hdr_t *)(uintptr_t)pkt;
}

static inline odp_packet_t packet_handle(odp_packet_hdr_t *pkt_hdr)
{
	return (odp_packet_t)pkt_hdr;
}

static inline void copy_packet_parser_metadata(odp_packet_hdr_t *src_hdr,
					       odp_packet_hdr_t *dst_hdr)
{
	dst_hdr->p = src_hdr->p;
}

static inline void copy_packet_cls_metadata(odp_packet_hdr_t *src_hdr,
					    odp_packet_hdr_t *dst_hdr)
{
	dst_hdr->p = src_hdr->p;
	dst_hdr->dst_queue = src_hdr->dst_queue;
	dst_hdr->flow_hash = src_hdr->flow_hash;
	dst_hdr->timestamp = src_hdr->timestamp;
	dst_hdr->op_result = src_hdr->op_result;
}

static inline void pull_tail(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	int last = pkt_hdr->buf_hdr.segcount - 1;

	pkt_hdr->tailroom  += len;
	pkt_hdr->frame_len -= len;
	pkt_hdr->buf_hdr.seg[last].len -= len;
}

static inline uint32_t packet_len(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->frame_len;
}

static inline void packet_set_len(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	pkt_hdr->frame_len = len;
}

#ifdef MV_NETMAP_BUF_ZERO_COPY
static inline int is_packet_buf_ext(odp_packet_t pkt)
{
	return is_ext_buffer(&odp_packet_hdr(pkt)->buf_hdr);
}

static inline void packet_ext_buf_swap(odp_packet_t		pkt,
				       void			*buf,
				       uint16_t			size,
				       struct netmap_ring	*ring,
				       uint32_t			buf_idx,
				       uint16_t			data_offs)
{
	seg_swap_ext_buf(&odp_packet_hdr(pkt)->buf_hdr,
			 buf,
			 size,
			 ring,
			 buf_idx,
			 data_offs);
}

static inline void packet_orig_buf_swap(odp_packet_t		pkt,
					struct netmap_ring	**ring,
					uint32_t		*buf_idx,
					uint16_t		*data_offs)
{
	seg_swap_orig_buf(&odp_packet_hdr(pkt)->buf_hdr,
			  ring,
			  buf_idx,
			  data_offs);
}
#endif /* MV_NETMAP_BUF_ZERO_COPY */
/* Forward declarations */
int _odp_packet_copy_md_to_packet(odp_packet_t srcpkt, odp_packet_t dstpkt);

/* Packet alloc of pktios */
int packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
		       odp_packet_t pkt[], int max_num);

/* Perform packet parse up to a given protocol layer */
int packet_parse_layer(odp_packet_hdr_t *pkt_hdr,
		       odp_pktio_parser_layer_t layer);

/* Reset parser metadata for a new parse */
void packet_parse_reset(odp_packet_hdr_t *pkt_hdr);

/* Convert a packet handle to a buffer handle */
odp_buffer_t _odp_packet_to_buffer(odp_packet_t pkt);

/* Convert a buffer handle to a packet handle */
odp_packet_t _odp_packet_from_buffer(odp_buffer_t buf);

static inline int packet_hdr_has_l2(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->p.input_flags.l2;
}

static inline void packet_hdr_has_l2_set(odp_packet_hdr_t *pkt_hdr, int val)
{
	pkt_hdr->p.input_flags.l2 = val;
}

static inline int packet_hdr_has_eth(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->p.input_flags.eth;
}

static inline int packet_hdr_has_ipv6(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->p.input_flags.ipv6;
}

static inline void packet_set_ts(odp_packet_hdr_t *pkt_hdr, odp_time_t *ts)
{
	if (ts != NULL) {
		pkt_hdr->timestamp = *ts;
		pkt_hdr->p.input_flags.timestamp = 1;
	}
}

int packet_parse_common(packet_parser_t *pkt_hdr, const uint8_t *ptr,
			uint32_t pkt_len, uint32_t seg_len,
			odp_pktio_parser_layer_t layer);

int _odp_cls_parse(odp_packet_hdr_t *pkt_hdr, const uint8_t *parseptr);

int _odp_packet_set_data(odp_packet_t pkt, uint32_t offset,
			 uint8_t c, uint32_t len);

int _odp_packet_cmp_data(odp_packet_t pkt, uint32_t offset,
			 const void *s, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
