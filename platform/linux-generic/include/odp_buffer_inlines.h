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
#include <odp_pool_internal.h>

#ifdef MV_NETMAP_BUF_ZERO_COPY
static inline int is_ext_buffer(odp_buffer_hdr_t *hdr)
{
	return !!hdr->netmap_buf_inf.orig_buf;
}
#endif /* MV_NETMAP_BUF_ZERO_COPY */

static inline odp_buffer_t odp_buffer_encode_handle(odp_buffer_hdr_t *hdr)
{
	odp_buffer_bits_t handle;
	uint32_t pool_id = pool_handle_to_index(hdr->pool_hdl);
	struct pool_entry_s *pool = get_pool_entry(pool_id);

	handle.handle = 0;
	handle.pool_id = pool_id;
	handle.index = ((uint8_t *)hdr - pool->pool_mdata_addr) /
		ODP_CACHE_LINE_SIZE;
	handle.seg = 0;

	return handle.handle;
}

static inline odp_buffer_t odp_hdr_to_buf(odp_buffer_hdr_t *hdr)
{
	return hdr->handle.handle;
}

static inline odp_buffer_hdr_t *odp_buf_to_hdr(odp_buffer_t buf)
{
	odp_buffer_bits_t handle;
	uint32_t pool_id;
	uint32_t index;
	struct pool_entry_s *pool;

	handle.handle = buf;
	pool_id       = handle.pool_id;
	index         = handle.index;
	pool          = get_pool_entry(pool_id);

	return (odp_buffer_hdr_t *)(void *)
		(pool->pool_mdata_addr + (index * ODP_CACHE_LINE_SIZE));
}

static inline uint32_t pool_id_from_buf(odp_buffer_t buf)
{
	odp_buffer_bits_t handle;

	handle.handle = buf;
	return handle.pool_id;
}

static inline odp_buffer_hdr_t *validate_buf(odp_buffer_t buf)
{
	odp_buffer_bits_t handle;
	odp_buffer_hdr_t *buf_hdr;
	handle.handle = buf;

	/* For buffer handles, segment index must be 0 and pool id in range */
	if (handle.seg != 0 || handle.pool_id >= ODP_CONFIG_POOLS)
		return NULL;

	pool_entry_t *pool =
		odp_pool_to_entry(_odp_cast_scalar(odp_pool_t,
						   handle.pool_id));

	/* If pool not created, handle is invalid */
	if (pool->s.pool_shm == ODP_SHM_INVALID)
		return NULL;

	uint32_t buf_stride = pool->s.buf_stride / ODP_CACHE_LINE_SIZE;

	/* A valid buffer index must be on stride, and must be in range */
	if ((handle.index % buf_stride != 0) ||
	    ((uint32_t)(handle.index / buf_stride) >= pool->s.params.buf.num))
		return NULL;

	buf_hdr = (odp_buffer_hdr_t *)(void *)
		(pool->s.pool_mdata_addr +
		 (handle.index * ODP_CACHE_LINE_SIZE));

	/* Handle is valid, so buffer is valid if it is allocated */
	return buf_hdr->allocator == ODP_FREEBUF ? NULL : buf_hdr;
}

int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf);

static inline void *buffer_map(odp_buffer_hdr_t *buf,
			       uint32_t offset,
			       uint32_t *seglen,
			       uint32_t limit)
{
	int seg_index;
	int seg_offset;

	if (odp_likely(offset < buf->segsize)) {
		seg_index = 0;
		seg_offset = offset;
	} else {
		seg_index  = offset / buf->segsize;
		seg_offset = offset % buf->segsize;
	}
	if (seglen != NULL) {
		uint32_t buf_left = limit - offset;
		*seglen = seg_offset + buf_left <= buf->segsize ?
			buf_left : buf->segsize - seg_offset;
	}

	return (void *)(seg_offset + (uint8_t *)buf->addr[seg_index]);
}

static inline odp_buffer_seg_t segment_next(odp_buffer_hdr_t *buf,
					    odp_buffer_seg_t seg)
{
	odp_buffer_bits_t seghandle;
	seghandle.handle = (odp_buffer_t)seg;

	if (seg == ODP_SEGMENT_INVALID ||
	    seghandle.prefix != buf->handle.prefix ||
	    seghandle.seg >= buf->segcount - 1)
		return ODP_SEGMENT_INVALID;
	else {
		seghandle.seg++;
		return (odp_buffer_seg_t)seghandle.handle;
	}
}

static inline void *segment_map(odp_buffer_hdr_t *buf,
				odp_buffer_seg_t seg,
				uint32_t *seglen,
				uint32_t limit,
				uint32_t hr)
{
	uint32_t seg_offset, buf_left;
	odp_buffer_bits_t seghandle;
	uint8_t *seg_addr;
	seghandle.handle = (odp_buffer_t)seg;

	if (seghandle.prefix != buf->handle.prefix ||
	    seghandle.seg >= buf->segcount)
		return NULL;

	seg_addr   = (uint8_t *)buf->addr[seghandle.seg];
	seg_offset = seghandle.seg * buf->segsize;
	limit     += hr;

	/* Can't map this segment if it's nothing but headroom or tailroom */
	if (hr >= seg_offset + buf->segsize || seg_offset > limit)
		return NULL;

	/* Adjust address & offset if this segment contains any headroom */
	if (hr > seg_offset) {
		seg_addr   += hr % buf->segsize;
		seg_offset += hr % buf->segsize;
	}

	/* Set seglen if caller is asking for it */
	if (seglen != NULL) {
		buf_left = limit - seg_offset;
		*seglen = buf_left < buf->segsize ? buf_left :
			(seg_offset >= buf->segsize ? buf->segsize :
			 buf->segsize - seg_offset);
	}

	return (void *)seg_addr;
}

static inline odp_event_type_t _odp_buffer_event_type(odp_buffer_t buf)
{
	return odp_buf_to_hdr(buf)->event_type;
}

static inline void _odp_buffer_event_type_set(odp_buffer_t buf, int ev)
{
	odp_buf_to_hdr(buf)->event_type = ev;
}

#ifdef MV_NETMAP_BUF_ZERO_COPY
static inline void seg_swap_ext_buf(odp_buffer_hdr_t	*buf_hdr,
				    void		*buf,
				    uint32_t		 size,
				    struct netmap_ring	*ring,
				    uint32_t		 buf_idx,
				    uint16_t		 data_offs
				   )
{
	buf_hdr->netmap_buf_inf.orig_buf = buf_hdr->addr[0];
	buf_hdr->addr[0] = buf;
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
	buf_hdr->addr[0] = buf_hdr->netmap_buf_inf.orig_buf;
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
