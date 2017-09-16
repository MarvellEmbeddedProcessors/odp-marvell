/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * Inline functions for ODP buffer mgmt routines - implementation internal
 */

#ifndef ODP_BUFFER_INLINES_H_
#define ODP_BUFFER_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_buffer_internal.h>

odp_event_type_t _odp_buffer_event_type(odp_buffer_t buf);
void _odp_buffer_event_type_set(odp_buffer_t buf, int ev);
int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf);

static inline odp_buffer_t odp_hdr_to_buf(odp_buffer_hdr_t *hdr)
{
	return hdr->handle.handle;
}

#ifdef MV_NETMAP_BUF_ZERO_COPY
static inline int is_ext_buffer(odp_buffer_hdr_t *hdr)
{
	return !!hdr->netmap_buf_inf.orig_buf;
}

int netmap_pkt_free(odp_buffer_t buf);

static inline void seg_swap_ext_buf(odp_buffer_hdr_t	*buf_hdr,
				    void		*buf,
				    uint32_t		 size,
				    struct netmap_ring	*ring,
				    uint32_t		 buf_idx,
				    uint16_t		 data_offs
				   )
{
	buf_hdr->ext_buf_free_cb = netmap_pkt_free;
	buf_hdr->netmap_buf_inf.orig_buf = buf_hdr->seg[0].data;
	buf_hdr->seg[0].data = buf;
	buf_hdr->netmap_buf_inf.orig_size = buf_hdr->size;
	buf_hdr->size = size;
	buf_hdr->netmap_buf_inf.orig_num_segs = buf_hdr->segcount;
	buf_hdr->segcount = 1;
	buf_hdr->netmap_buf_inf.ring = ring;
	buf_hdr->netmap_buf_inf.buf_idx = buf_idx;
	buf_hdr->netmap_buf_inf.data_offs = data_offs;
}

static inline void seg_swap_orig_buf(odp_buffer_hdr_t	 *buf_hdr,
				     struct netmap_ring	**ring,
				     uint32_t		 *buf_idx,
				     uint16_t		 *data_offs
				    )
{
	buf_hdr->ext_buf_free_cb = NULL;
	buf_hdr->seg[0].data = buf_hdr->netmap_buf_inf.orig_buf;
	buf_hdr->netmap_buf_inf.orig_buf = NULL;
	buf_hdr->size = buf_hdr->netmap_buf_inf.orig_size;
	buf_hdr->segcount = buf_hdr->netmap_buf_inf.orig_num_segs;
	*ring = buf_hdr->netmap_buf_inf.ring;
	*buf_idx = buf_hdr->netmap_buf_inf.buf_idx;
	*data_offs = buf_hdr->netmap_buf_inf.data_offs;
}
#endif /* MV_NETMAP_BUF_ZERO_COPY */
#ifdef __cplusplus
}
#endif

#endif
