/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/std_types.h>
#include <odp/api/pool.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_packet_internal.h>
#include <odp_timer_internal.h>
#include <odp_align_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/align.h>
#include <odp_internal.h>
#include <odp_config_internal.h>
#include <odp/api/hints.h>
#include <odp/api/thread.h>
#include <odp_debug_internal.h>

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#if ODP_CONFIG_POOLS > ODP_BUFFER_MAX_POOLS
#error ODP_CONFIG_POOLS > ODP_BUFFER_MAX_POOLS
#endif


typedef union buffer_type_any_u {
	odp_buffer_hdr_t  buf;
	odp_packet_hdr_t  pkt;
	odp_timeout_hdr_t tmo;
} odp_anybuf_t;

/* Any buffer type header */
typedef struct {
	union buffer_type_any_u any_hdr;    /* any buffer type */
} odp_any_buffer_hdr_t;

typedef struct odp_any_hdr_stride {
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_any_buffer_hdr_t))];
} odp_any_hdr_stride;


typedef struct pool_table_t {
	pool_entry_t pool[ODP_CONFIG_POOLS];
} pool_table_t;


/* The pool table */
static pool_table_t *pool_tbl;
static const char SHM_DEFAULT_NAME[] = "odp_buffer_pools";

/* Pool entry pointers (for inlining) */
void *pool_entry_ptr[ODP_CONFIG_POOLS];

/* Thread local variables */
typedef struct pool_local_t {
	local_cache_t *cache[ODP_CONFIG_POOLS];
	int thr_id;
} pool_local_t;

static __thread pool_local_t local;

#ifdef MV_NETMAP_BUF_ZERO_COPY
int (*ext_buf_free_cb)(odp_buffer_t buf) = NULL;
#endif /* MV_NETMAP_BUF_ZERO_COPY */

static void flush_cache(local_cache_t *buf_cache, struct pool_entry_s *pool);

int odp_pool_init_global(void)
{
	uint32_t i;
	odp_shm_t shm;

	shm = odp_shm_reserve(SHM_DEFAULT_NAME,
			      sizeof(pool_table_t),
			      sizeof(pool_entry_t), 0);

	pool_tbl = odp_shm_addr(shm);

	if (pool_tbl == NULL)
		return -1;

	memset(pool_tbl, 0, sizeof(pool_table_t));

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		/* init locks */
		pool_entry_t *pool = &pool_tbl->pool[i];
		POOL_LOCK_INIT(&pool->s.lock);
		POOL_LOCK_INIT(&pool->s.buf_lock);
		POOL_LOCK_INIT(&pool->s.blk_lock);
		pool->s.pool_hdl = pool_index_to_handle(i);
		pool->s.pool_id = i;
		pool_entry_ptr[i] = pool;
		odp_atomic_init_u32(&pool->s.bufcount, 0);
		odp_atomic_init_u32(&pool->s.blkcount, 0);

		/* Initialize pool statistics counters */
		odp_atomic_init_u64(&pool->s.poolstats.bufallocs, 0);
		odp_atomic_init_u64(&pool->s.poolstats.buffrees, 0);
		odp_atomic_init_u64(&pool->s.poolstats.blkallocs, 0);
		odp_atomic_init_u64(&pool->s.poolstats.blkfrees, 0);
		odp_atomic_init_u64(&pool->s.poolstats.bufempty, 0);
		odp_atomic_init_u64(&pool->s.poolstats.blkempty, 0);
		odp_atomic_init_u64(&pool->s.poolstats.buf_high_wm_count, 0);
		odp_atomic_init_u64(&pool->s.poolstats.buf_low_wm_count, 0);
		odp_atomic_init_u64(&pool->s.poolstats.blk_high_wm_count, 0);
		odp_atomic_init_u64(&pool->s.poolstats.blk_low_wm_count, 0);
	}

	ODP_DBG("\nPool init global\n");
	ODP_DBG("  pool_entry_s size     %zu\n", sizeof(struct pool_entry_s));
	ODP_DBG("  pool_entry_t size     %zu\n", sizeof(pool_entry_t));
	ODP_DBG("  odp_buffer_hdr_t size %zu\n", sizeof(odp_buffer_hdr_t));
	ODP_DBG("\n");
	return 0;
}

int odp_pool_init_local(void)
{
	pool_entry_t *pool;
	int i;
	int thr_id = odp_thread_id();

	memset(&local, 0, sizeof(pool_local_t));

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool           = get_pool_entry(i);
		local.cache[i] = &pool->s.local_cache[thr_id];
		local.cache[i]->s.num_buf = 0;
	}

	local.thr_id = thr_id;
	return 0;
}

int odp_pool_term_global(void)
{
	int i;
	pool_entry_t *pool;
	int ret = 0;
	int rc = 0;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = get_pool_entry(i);

		POOL_LOCK(&pool->s.lock);
		if (pool->s.pool_shm != ODP_SHM_INVALID) {
			ODP_ERR("Not destroyed pool: %s\n", pool->s.name);
			rc = -1;
		}
		POOL_UNLOCK(&pool->s.lock);
	}

	ret = odp_shm_free(odp_shm_lookup(SHM_DEFAULT_NAME));
	if (ret < 0) {
		ODP_ERR("shm free failed for %s", SHM_DEFAULT_NAME);
		rc = -1;
	}

	return rc;
}

int odp_pool_term_local(void)
{
	int i;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool_entry_t *pool = get_pool_entry(i);

		flush_cache(local.cache[i], &pool->s);
	}

	return 0;
}

int odp_pool_capability(odp_pool_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_pool_capability_t));

	capa->max_pools = ODP_CONFIG_POOLS;

	/* Buffer pools */
	capa->buf.max_pools = ODP_CONFIG_POOLS;
	capa->buf.max_align = ODP_CONFIG_BUFFER_ALIGN_MAX;
	capa->buf.max_size  = 0;
	capa->buf.max_num   = 0;

	/* Packet pools */
	capa->pkt.max_pools        = ODP_CONFIG_POOLS;
	capa->pkt.max_len          = ODP_CONFIG_PACKET_MAX_SEGS *
				     ODP_CONFIG_PACKET_SEG_LEN_MIN;
	capa->pkt.max_num	   = 0;
	capa->pkt.min_headroom     = ODP_CONFIG_PACKET_HEADROOM;
	capa->pkt.min_tailroom     = ODP_CONFIG_PACKET_TAILROOM;
	capa->pkt.max_segs_per_pkt = ODP_CONFIG_PACKET_MAX_SEGS;
	capa->pkt.min_seg_len      = ODP_CONFIG_PACKET_SEG_LEN_MIN;
	capa->pkt.max_seg_len      = ODP_CONFIG_PACKET_SEG_LEN_MAX;
	capa->pkt.max_uarea_size   = 0;

	/* Timeout pools */
	capa->tmo.max_pools = ODP_CONFIG_POOLS;
	capa->tmo.max_num   = 0;

	return 0;
}

static inline odp_buffer_hdr_t *get_buf(struct pool_entry_s *pool)
{
	odp_buffer_hdr_t *myhead;

	POOL_LOCK(&pool->buf_lock);

	myhead = pool->buf_freelist;

	if (odp_unlikely(myhead == NULL)) {
		POOL_UNLOCK(&pool->buf_lock);
		odp_atomic_inc_u64(&pool->poolstats.bufempty);
	} else {
		pool->buf_freelist = myhead->next;
		POOL_UNLOCK(&pool->buf_lock);

		odp_atomic_fetch_sub_u32(&pool->bufcount, 1);
		odp_atomic_inc_u64(&pool->poolstats.bufallocs);
	}

	return (void *)myhead;
}

static inline void ret_buf(struct pool_entry_s *pool, odp_buffer_hdr_t *buf)
{
	if (!buf->flags.hdrdata && buf->type != ODP_EVENT_BUFFER) {
		while (buf->segcount > 0) {
			if (buffer_is_secure(buf) || pool_is_secure(pool))
				memset(buf->addr[buf->segcount - 1],
				       0, buf->segsize);
			ret_blk(pool, buf->addr[--buf->segcount]);
		}
		buf->size = 0;
	}

	buf->allocator = ODP_FREEBUF;  /* Mark buffer free */
	POOL_LOCK(&pool->buf_lock);
	buf->next = pool->buf_freelist;
	pool->buf_freelist = buf;
	POOL_UNLOCK(&pool->buf_lock);

	odp_atomic_fetch_add_u32(&pool->bufcount, 1);
	odp_atomic_inc_u64(&pool->poolstats.buffrees);
}

/*
 * Pool creation
 */
odp_pool_t _pool_create(const char *name,
			odp_pool_param_t *params,
			uint32_t shmflags)
{
	odp_pool_t pool_hdl = ODP_POOL_INVALID;
	pool_entry_t *pool;
	uint32_t i, headroom = 0, tailroom = 0;
	odp_shm_t shm;

	if (params == NULL)
		return ODP_POOL_INVALID;

	/* Default size and align for timeouts */
	if (params->type == ODP_POOL_TIMEOUT) {
		params->buf.size  = 0; /* tmo.__res1 */
		params->buf.align = 0; /* tmo.__res2 */
	}

	/* Default initialization parameters */
	uint32_t p_udata_size = 0;
	uint32_t udata_stride = 0;

	/* Restriction for v1.0: All non-packet buffers are unsegmented */
	int unseg = 1;

	uint32_t blk_size, buf_stride, buf_num, blk_num, seg_len = 0;
	uint32_t buf_align =
		params->type == ODP_POOL_BUFFER ? params->buf.align : 0;

	/* Validate requested buffer alignment */
	if (buf_align > ODP_CONFIG_BUFFER_ALIGN_MAX ||
	    buf_align != ODP_ALIGN_ROUNDDOWN_POWER_2(buf_align, buf_align))
		return ODP_POOL_INVALID;

	/* Set correct alignment based on input request */
	if (buf_align == 0)
		buf_align = ODP_CACHE_LINE_SIZE;
	else if (buf_align < ODP_CONFIG_BUFFER_ALIGN_MIN)
		buf_align = ODP_CONFIG_BUFFER_ALIGN_MIN;

	/* Calculate space needed for buffer blocks and metadata */
	switch (params->type) {
	case ODP_POOL_BUFFER:
		buf_num  = params->buf.num;
		blk_size = params->buf.size;

		/* Optimize small raw buffers */
		if (blk_size > ODP_MAX_INLINE_BUF || params->buf.align != 0)
			blk_size = ODP_ALIGN_ROUNDUP(blk_size, buf_align);

		buf_stride = sizeof(odp_buffer_hdr_stride);
		break;

	case ODP_POOL_PACKET:
		unseg = 0; /* Packets are always segmented */
		headroom = ODP_CONFIG_PACKET_HEADROOM;
		tailroom = ODP_CONFIG_PACKET_TAILROOM;
		buf_num = params->pkt.num;

		seg_len = params->pkt.seg_len <= ODP_CONFIG_PACKET_SEG_LEN_MIN ?
			ODP_CONFIG_PACKET_SEG_LEN_MIN :
			(params->pkt.seg_len <= ODP_CONFIG_PACKET_SEG_LEN_MAX ?
			 params->pkt.seg_len : ODP_CONFIG_PACKET_SEG_LEN_MAX);

		seg_len = ODP_ALIGN_ROUNDUP(
			headroom + seg_len + tailroom,
			ODP_CONFIG_BUFFER_ALIGN_MIN);

		blk_size = params->pkt.len <= seg_len ? seg_len :
			ODP_ALIGN_ROUNDUP(params->pkt.len, seg_len);

		/* Reject create if pkt.len needs too many segments */
		if (blk_size / seg_len > ODP_BUFFER_MAX_SEG) {
			ODP_ERR("ODP_BUFFER_MAX_SEG exceed %d(%d)\n",
				blk_size / seg_len, ODP_BUFFER_MAX_SEG);
			return ODP_POOL_INVALID;
		}

		p_udata_size = params->pkt.uarea_size;
		udata_stride = ODP_ALIGN_ROUNDUP(p_udata_size,
						 sizeof(uint64_t));

		buf_stride = sizeof(odp_packet_hdr_stride);
		break;

	case ODP_POOL_TIMEOUT:
		blk_size = 0;
		buf_num = params->tmo.num;
		buf_stride = sizeof(odp_timeout_hdr_stride);
		break;

	default:
		return ODP_POOL_INVALID;
	}

	/* Validate requested number of buffers against addressable limits */
	if (buf_num >
	    (ODP_BUFFER_MAX_BUFFERS / (buf_stride / ODP_CACHE_LINE_SIZE))) {
		ODP_ERR("buf_num %d > then expected %d\n",
			buf_num, ODP_BUFFER_MAX_BUFFERS /
			(buf_stride / ODP_CACHE_LINE_SIZE));
		return ODP_POOL_INVALID;
	}

	/* Find an unused buffer pool slot and iniitalize it as requested */
	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = get_pool_entry(i);

		POOL_LOCK(&pool->s.lock);
		if (pool->s.pool_shm != ODP_SHM_INVALID) {
			POOL_UNLOCK(&pool->s.lock);
			continue;
		}

		/* found free pool */
		size_t block_size, pad_size, mdata_size, udata_size;

		pool->s.flags.all = 0;

		if (name == NULL) {
			pool->s.name[0] = 0;
		} else {
			strncpy(pool->s.name, name,
				ODP_POOL_NAME_LEN - 1);
			pool->s.name[ODP_POOL_NAME_LEN - 1] = 0;
			pool->s.flags.has_name = 1;
		}

		pool->s.params = *params;
		pool->s.buf_align = buf_align;

		/* Optimize for short buffers: Data stored in buffer hdr */
		if (blk_size <= ODP_MAX_INLINE_BUF) {
			block_size = 0;
			pool->s.buf_align = blk_size == 0 ? 0 : sizeof(void *);
		} else {
			block_size = buf_num * blk_size;
			pool->s.buf_align = buf_align;
		}

		pad_size = ODP_CACHE_LINE_SIZE_ROUNDUP(block_size) - block_size;
		mdata_size = buf_num * buf_stride;
		udata_size = buf_num * udata_stride;

		pool->s.buf_num   = buf_num;
		pool->s.pool_size = ODP_PAGE_SIZE_ROUNDUP(block_size +
							  pad_size +
							  mdata_size +
							  udata_size);

		shm = odp_shm_reserve(pool->s.name,
				      pool->s.pool_size,
				      ODP_PAGE_SIZE, shmflags);
		if (shm == ODP_SHM_INVALID) {
			POOL_UNLOCK(&pool->s.lock);
			return ODP_POOL_INVALID;
		}
		pool->s.pool_base_addr = odp_shm_addr(shm);
		pool->s.pool_shm = shm;

		/* Now safe to unlock since pool entry has been allocated */
		POOL_UNLOCK(&pool->s.lock);

		pool->s.flags.unsegmented = unseg;
		pool->s.seg_size = unseg ? blk_size : seg_len;
		pool->s.blk_size = blk_size;

		uint8_t *block_base_addr = pool->s.pool_base_addr;
		uint8_t *mdata_base_addr =
			block_base_addr + block_size + pad_size;
		uint8_t *udata_base_addr = mdata_base_addr + mdata_size;

		/* Pool mdata addr is used for indexing buffer metadata */
		pool->s.pool_mdata_addr = mdata_base_addr;
		pool->s.udata_size = p_udata_size;

		pool->s.buf_stride = buf_stride;
		pool->s.buf_freelist = NULL;
		pool->s.blk_freelist = NULL;

		/* Initialization will increment these to their target vals */
		odp_atomic_store_u32(&pool->s.bufcount, 0);
		odp_atomic_store_u32(&pool->s.blkcount, 0);

		uint8_t *buf = udata_base_addr - buf_stride;
		uint8_t *udat = udata_stride == 0 ? NULL :
			udata_base_addr + udata_size - udata_stride;

		/* Init buffer common header and add to pool buffer freelist */
		do {
			odp_buffer_hdr_t *tmp =
				(odp_buffer_hdr_t *)(void *)buf;

			/* Iniitalize buffer metadata */
			tmp->allocator = ODP_FREEBUF;
			tmp->flags.all = 0;
			tmp->size = 0;
			tmp->type = params->type;
			tmp->event_type = params->type;
			tmp->pool_hdl = pool->s.pool_hdl;
			tmp->uarea_addr = (void *)udat;
			tmp->uarea_size = p_udata_size;
			tmp->segcount = 0;
			tmp->segsize = pool->s.seg_size;
			tmp->handle.handle = odp_buffer_encode_handle(tmp);
#if defined(MV_NETMAP_BUF_ZERO_COPY) || defined(MV_MUSDK_FREE_BUF_SUPPORT)
			tmp->ext_buf_free_cb = NULL;
#endif
			/* Set 1st seg addr for zero-len buffers */
			tmp->addr[0] = NULL;

			/* Special case for short buffer data */
			if (blk_size <= ODP_MAX_INLINE_BUF) {
				tmp->flags.hdrdata = 1;
				if (blk_size > 0) {
					tmp->segcount = 1;
					tmp->addr[0] = &tmp->addr[1];
					tmp->size = blk_size;
				}
			}

			/* Push buffer onto pool's freelist */
			ret_buf(&pool->s, tmp);
			buf  -= buf_stride;
			udat -= udata_stride;
		} while (buf >= mdata_base_addr);

		/* Form block freelist for pool */
		uint8_t *blk =
			block_base_addr + block_size - pool->s.seg_size;

		if (blk_size > ODP_MAX_INLINE_BUF)
			do {
				ret_blk(&pool->s, blk);
				blk -= pool->s.seg_size;
			} while (blk >= block_base_addr);

		blk_num = odp_atomic_load_u32(&pool->s.blkcount);

		/* Initialize pool statistics counters */
		odp_atomic_store_u64(&pool->s.poolstats.bufallocs, 0);
		odp_atomic_store_u64(&pool->s.poolstats.buffrees, 0);
		odp_atomic_store_u64(&pool->s.poolstats.blkallocs, 0);
		odp_atomic_store_u64(&pool->s.poolstats.blkfrees, 0);
		odp_atomic_store_u64(&pool->s.poolstats.bufempty, 0);
		odp_atomic_store_u64(&pool->s.poolstats.blkempty, 0);
		odp_atomic_store_u64(&pool->s.poolstats.buf_high_wm_count, 0);
		odp_atomic_store_u64(&pool->s.poolstats.buf_low_wm_count, 0);
		odp_atomic_store_u64(&pool->s.poolstats.blk_high_wm_count, 0);
		odp_atomic_store_u64(&pool->s.poolstats.blk_low_wm_count, 0);

		/* Reset other pool globals to initial state */
		pool->s.buf_low_wm_assert = 0;
		pool->s.blk_low_wm_assert = 0;
		pool->s.quiesced = 0;
		pool->s.headroom = headroom;
		pool->s.tailroom = tailroom;

		/* Watermarks are hard-coded for now to control caching */
		pool->s.buf_high_wm = buf_num / 2;
		pool->s.buf_low_wm  = buf_num / 4;
		pool->s.blk_high_wm = blk_num / 2;
		pool->s.blk_low_wm = blk_num / 4;

		pool_hdl = pool->s.pool_hdl;
		break;
	}

	return pool_hdl;
}

odp_pool_t odp_pool_create(const char *name,
			   odp_pool_param_t *params)
{
#ifdef _ODP_PKTIO_IPC
	if (params && (params->type == ODP_POOL_PACKET))
		return _pool_create(name, params, ODP_SHM_PROC);
#endif
	return _pool_create(name, params, 0);

}

odp_pool_t odp_pool_lookup(const char *name)
{
	uint32_t i;
	pool_entry_t *pool;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = get_pool_entry(i);

		POOL_LOCK(&pool->s.lock);
		if (strcmp(name, pool->s.name) == 0) {
			/* found it */
			POOL_UNLOCK(&pool->s.lock);
			return pool->s.pool_hdl;
		}
		POOL_UNLOCK(&pool->s.lock);
	}

	return ODP_POOL_INVALID;
}

int odp_pool_info(odp_pool_t pool_hdl, odp_pool_info_t *info)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);

	if (pool == NULL || info == NULL)
		return -1;

	info->name = pool->s.name;
	info->params = pool->s.params;

	return 0;
}

static inline void get_local_cache_bufs(local_cache_t *buf_cache, uint32_t idx,
					odp_buffer_hdr_t *buf_hdr[],
					uint32_t num)
{
	uint32_t i;

	for (i = 0; i < num; i++) {
		buf_hdr[i] = buf_cache->s.buf[idx + i];
		odp_prefetch(buf_hdr[i]);
		odp_prefetch_store(buf_hdr[i]);
	}
}

static void flush_cache(local_cache_t *buf_cache, struct pool_entry_s *pool)
{
	uint32_t flush_count = 0;
	uint32_t num;

	while ((num = buf_cache->s.num_buf)) {
		odp_buffer_hdr_t *buf;

		buf = buf_cache->s.buf[num - 1];
		ret_buf(pool, buf);
		flush_count++;
		buf_cache->s.num_buf--;
	}

	odp_atomic_add_u64(&pool->poolstats.bufallocs, buf_cache->s.bufallocs);
	odp_atomic_add_u64(&pool->poolstats.buffrees,
			   buf_cache->s.buffrees - flush_count);

	buf_cache->s.bufallocs = 0;
	buf_cache->s.buffrees = 0;
}

int odp_pool_destroy(odp_pool_t pool_hdl)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	int i;

	if (pool == NULL)
		return -1;

	POOL_LOCK(&pool->s.lock);

	/* Call fails if pool is not allocated or predefined*/
	if (pool->s.pool_shm == ODP_SHM_INVALID ||
	    pool->s.flags.predefined) {
		POOL_UNLOCK(&pool->s.lock);
		ODP_ERR("invalid shm for pool %s\n", pool->s.name);
		return -1;
	}

	/* Make sure local caches are empty */
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++)
		flush_cache(&pool->s.local_cache[i], &pool->s);

	/* Call fails if pool has allocated buffers */
	if (odp_atomic_load_u32(&pool->s.bufcount) < pool->s.buf_num) {
		POOL_UNLOCK(&pool->s.lock);
		ODP_DBG("error: pool has allocated buffers %d/%d\n",
			odp_atomic_load_u32(&pool->s.bufcount),
			pool->s.buf_num);
		return -1;
	}

	odp_shm_free(pool->s.pool_shm);
	pool->s.pool_shm = ODP_SHM_INVALID;
	POOL_UNLOCK(&pool->s.lock);

	return 0;
}

int seg_alloc_head(odp_buffer_hdr_t *buf_hdr,  int segcount)
{
	uint32_t pool_id = pool_handle_to_index(buf_hdr->pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	void *newsegs[segcount];
	int i;

	for (i = 0; i < segcount; i++) {
		newsegs[i] = get_blk(&pool->s);
		if (newsegs[i] == NULL) {
			while (--i >= 0)
				ret_blk(&pool->s, newsegs[i]);
			return -1;
		}
	}

	for (i = buf_hdr->segcount - 1; i >= 0; i--)
		buf_hdr->addr[i + segcount] = buf_hdr->addr[i];

	for (i = 0; i < segcount; i++)
		buf_hdr->addr[i] = newsegs[i];

	buf_hdr->segcount += segcount;
	buf_hdr->size      = buf_hdr->segcount * pool->s.seg_size;
	return 0;
}

void seg_free_head(odp_buffer_hdr_t *buf_hdr, int segcount)
{
	uint32_t pool_id = pool_handle_to_index(buf_hdr->pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	int s_cnt = buf_hdr->segcount;
	int i;

	for (i = 0; i < segcount; i++)
		ret_blk(&pool->s, buf_hdr->addr[i]);

	for (i = 0; i < s_cnt - segcount; i++)
		buf_hdr->addr[i] = buf_hdr->addr[i + segcount];

	buf_hdr->segcount -= segcount;
	buf_hdr->size      = buf_hdr->segcount * pool->s.seg_size;
}

int seg_alloc_tail(odp_buffer_hdr_t *buf_hdr,  int segcount)
{
	uint32_t pool_id = pool_handle_to_index(buf_hdr->pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	uint32_t s_cnt = buf_hdr->segcount;
	int i;

	for (i = 0; i < segcount; i++) {
		buf_hdr->addr[s_cnt + i] = get_blk(&pool->s);
		if (buf_hdr->addr[s_cnt + i] == NULL) {
			while (--i >= 0)
				ret_blk(&pool->s, buf_hdr->addr[s_cnt + i]);
			return -1;
		}
	}

	buf_hdr->segcount += segcount;
	buf_hdr->size      = buf_hdr->segcount * pool->s.seg_size;
	return 0;
}

void seg_free_tail(odp_buffer_hdr_t *buf_hdr, int segcount)
{
	uint32_t pool_id = pool_handle_to_index(buf_hdr->pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	int s_cnt = buf_hdr->segcount;
	int i;

	for (i = s_cnt - 1; i >= s_cnt - segcount; i--)
		ret_blk(&pool->s, buf_hdr->addr[i]);

	buf_hdr->segcount -= segcount;
	buf_hdr->size      = buf_hdr->segcount * pool->s.seg_size;
}

static inline int get_local_bufs(local_cache_t *buf_cache,
				 odp_buffer_hdr_t *buf_hdr[], uint32_t max_num)
{
	uint32_t num_buf = buf_cache->s.num_buf;
	uint32_t num = num_buf;

	if (odp_unlikely(num_buf == 0))
		return 0;

	if (odp_likely(max_num < num))
		num = max_num;

	get_local_cache_bufs(buf_cache, num_buf - num, buf_hdr, num);
	buf_cache->s.num_buf   -= num;
	buf_cache->s.bufallocs += num;

	return num;
}

static inline void ret_local_buf(local_cache_t *buf_cache, uint32_t idx,
				 odp_buffer_hdr_t *buf)
{
	buf_cache->s.buf[idx] = buf;
	buf_cache->s.num_buf++;
	buf_cache->s.buffrees++;
}

static inline void ret_local_bufs(local_cache_t *buf_cache, uint32_t idx,
				  odp_buffer_hdr_t *buf[], int num_buf)
{
	int i;

	for (i = 0; i < num_buf; i++)
		buf_cache->s.buf[idx + i] = buf[i];

	buf_cache->s.num_buf  += num_buf;
	buf_cache->s.buffrees += num_buf;
}

int buffer_alloc_multi(odp_pool_t pool_hdl, size_t size,
		       odp_buffer_t buf[], int max_num)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	uintmax_t totsize = pool->s.headroom + size + pool->s.tailroom;
	odp_buffer_hdr_t *buf_tbl[max_num];
	odp_buffer_hdr_t *buf_hdr;
	int num, i;
	intmax_t needed;
	void *blk;

	/* Reject oversized allocation requests */
	if ((pool->s.flags.unsegmented && totsize > pool->s.seg_size) ||
	    (!pool->s.flags.unsegmented &&
	     totsize > pool->s.seg_size * ODP_BUFFER_MAX_SEG))
		return 0;

	/* Try to satisfy request from the local cache */
	num = get_local_bufs(local.cache[pool_id], buf_tbl, max_num);

	/* If cache is empty, satisfy request from the pool */
	if (odp_unlikely(num < max_num)) {
		for (; num < max_num; num++) {
			buf_hdr = get_buf(&pool->s);

			if (odp_unlikely(buf_hdr == NULL))
				goto pool_empty;

			/* Get blocks for this buffer, if pool uses
			 * application data */
			if (buf_hdr->size < totsize) {
				uint32_t segcount;

				needed = totsize - buf_hdr->size;
				do {
					blk = get_blk(&pool->s);
					if (odp_unlikely(blk == NULL)) {
						ret_buf(&pool->s, buf_hdr);
						goto pool_empty;
					}

					segcount = buf_hdr->segcount++;
					buf_hdr->addr[segcount] = blk;
					needed -= pool->s.seg_size;
				} while (needed > 0);
				buf_hdr->size = buf_hdr->segcount *
						pool->s.seg_size;
			}

			buf_tbl[num] = buf_hdr;
		}
	}

pool_empty:
	for (i = 0; i < num; i++) {
		buf_hdr = buf_tbl[i];

		/* Mark buffer as allocated */
		buf_hdr->allocator = local.thr_id;

		/* By default, buffers are not associated with
		 * an ordered queue */
		buf_hdr->origin_qe = NULL;

		buf[i] = odp_hdr_to_buf(buf_hdr);

		/* Add more segments if buffer from local cache is too small */
		if (odp_unlikely(buf_hdr->size < totsize)) {
			needed = totsize - buf_hdr->size;
			do {
				blk = get_blk(&pool->s);
				if (odp_unlikely(blk == NULL)) {
					int j;

					ret_buf(&pool->s, buf_hdr);
					buf_hdr = NULL;
					local.cache[pool_id]->s.buffrees--;

					/* move remaining bufs up one step
					 * and update loop counters */
					num--;
					for (j = i; j < num; j++)
						buf_tbl[j] = buf_tbl[j + 1];

					i--;
					break;
				}
				needed -= pool->s.seg_size;
				buf_hdr->addr[buf_hdr->segcount++] = blk;
				buf_hdr->size = buf_hdr->segcount *
						pool->s.seg_size;
			} while (needed > 0);
		}
	}

	return num;
}

odp_buffer_t buffer_alloc(odp_pool_t pool_hdl, size_t size)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	uintmax_t totsize = pool->s.headroom + size + pool->s.tailroom;
	odp_buffer_hdr_t *buf_hdr;
	intmax_t needed;
	void *blk;

	/* Reject oversized allocation requests */
	if ((pool->s.flags.unsegmented && totsize > pool->s.seg_size) ||
	    (!pool->s.flags.unsegmented &&
	     totsize > pool->s.seg_size * ODP_BUFFER_MAX_SEG))
		return 0;

	/* Try to satisfy request from the local cache. If cache is empty,
	 * satisfy request from the pool */
	if (odp_unlikely(!get_local_bufs(local.cache[pool_id], &buf_hdr, 1))) {
		buf_hdr = get_buf(&pool->s);

		if (odp_unlikely(buf_hdr == NULL))
			return ODP_BUFFER_INVALID;

		/* Get blocks for this buffer, if pool uses application data */
		if (buf_hdr->size < totsize) {
			needed = totsize - buf_hdr->size;
			do {
				blk = get_blk(&pool->s);
				if (odp_unlikely(blk == NULL)) {
					ret_buf(&pool->s, buf_hdr);
					return ODP_BUFFER_INVALID;
				}
				buf_hdr->addr[buf_hdr->segcount++] = blk;
				needed -= pool->s.seg_size;
			} while (needed > 0);
			buf_hdr->size = buf_hdr->segcount * pool->s.seg_size;
		}
	}
	/* Mark buffer as allocated */
	buf_hdr->allocator = local.thr_id;

	/* By default, buffers are not associated with
	 * an ordered queue */
	buf_hdr->origin_qe = NULL;

	/* Add more segments if buffer from local cache is too small */
	if (odp_unlikely(buf_hdr->size < totsize)) {
		needed = totsize - buf_hdr->size;
		do {
			blk = get_blk(&pool->s);
			if (odp_unlikely(blk == NULL)) {
				ret_buf(&pool->s, buf_hdr);
				buf_hdr = NULL;
				local.cache[pool_id]->s.buffrees--;
				return ODP_BUFFER_INVALID;
			}
			buf_hdr->addr[buf_hdr->segcount++] = blk;
			needed -= pool->s.seg_size;
		} while (needed > 0);
		buf_hdr->size = buf_hdr->segcount * pool->s.seg_size;
	}

	return odp_hdr_to_buf(buf_hdr);
}

odp_buffer_t odp_buffer_alloc(odp_pool_t pool_hdl)
{
	return buffer_alloc(pool_hdl,
			    odp_pool_to_entry(pool_hdl)->s.params.buf.size);
}

int odp_buffer_alloc_multi(odp_pool_t pool_hdl, odp_buffer_t buf[], int num)
{
	size_t buf_size = odp_pool_to_entry(pool_hdl)->s.params.buf.size;

	return buffer_alloc_multi(pool_hdl, buf_size, buf, num);
}

static void multi_pool_free(odp_buffer_hdr_t *buf_hdr[], int num_buf)
{
	uint32_t pool_id, num;
	local_cache_t *buf_cache;
	pool_entry_t *pool;
	int i, j, idx;

	for (i = 0; i < num_buf; i++) {
		pool_id   =  pool_handle_to_index(buf_hdr[i]->pool_hdl);
		buf_cache = local.cache[pool_id];
		num       = buf_cache->s.num_buf;

		if (num < POOL_MAX_LOCAL_BUFS) {
			ret_local_buf(buf_cache, num, buf_hdr[i]);
			continue;
		}

		idx  = POOL_MAX_LOCAL_BUFS - POOL_CHUNK_SIZE;
		pool = get_pool_entry(pool_id);

		/* local cache full, return a chunk */
		for (j = 0; j < POOL_CHUNK_SIZE; j++) {
			odp_buffer_hdr_t *tmp;

			tmp = buf_cache->s.buf[idx + i];
			ret_buf(&pool->s, tmp);
		}

		num = POOL_MAX_LOCAL_BUFS - POOL_CHUNK_SIZE;
		buf_cache->s.num_buf = num;
		ret_local_buf(buf_cache, num, buf_hdr[i]);
	}
}

void buffer_free_multi(uint32_t pool_id,
		       const odp_buffer_t buf[], int num_free)
{
	local_cache_t *buf_cache = local.cache[pool_id];
	uint32_t num;
	int i, idx;
	pool_entry_t *pool;
	odp_buffer_hdr_t *buf_hdr[num_free];
	int multi_pool = 0;

#if defined(MV_NETMAP_BUF_ZERO_COPY) || defined(MV_MUSDK_FREE_BUF_SUPPORT)
	for (i = 0; i < num_free; i++)
		buffer_free(pool_id_from_buf(buf[i]), buf[i]);
	return;
#endif /* MV_NETMAP_BUF_ZERO_COPY || MV_MUSDK_FREE_BUF_SUPPORT */

	for (i = 0; i < num_free; i++) {
		uint32_t id;

		buf_hdr[i] = odp_buf_to_hdr(buf[i]);
		ODP_ASSERT(buf_hdr[i]->allocator != ODP_FREEBUF);
		buf_hdr[i]->allocator = ODP_FREEBUF;
		id = pool_handle_to_index(buf_hdr[i]->pool_hdl);
		multi_pool |= (pool_id != id);
	}

	if (odp_unlikely(multi_pool)) {
		multi_pool_free(buf_hdr, num_free);
		return;
	}

	num = buf_cache->s.num_buf;

	if (odp_likely((num + num_free) < POOL_MAX_LOCAL_BUFS)) {
		ret_local_bufs(buf_cache, num, buf_hdr, num_free);
		return;
	}

	pool = get_pool_entry(pool_id);

	/* Return at least one chunk into the global pool */
	if (odp_unlikely(num_free > POOL_CHUNK_SIZE)) {
		for (i = 0; i < num_free; i++)
			ret_buf(&pool->s, buf_hdr[i]);

		return;
	}

	idx = num - POOL_CHUNK_SIZE;
	for (i = 0; i < POOL_CHUNK_SIZE; i++)
		ret_buf(&pool->s, buf_cache->s.buf[idx + i]);

	num -= POOL_CHUNK_SIZE;
	buf_cache->s.num_buf = num;
	ret_local_bufs(buf_cache, num, buf_hdr, num_free);
}

void buffer_free(uint32_t pool_id, const odp_buffer_t buf)
{
	local_cache_t *buf_cache = local.cache[pool_id];
	uint32_t num;
	int i;
	pool_entry_t *pool;
	odp_buffer_hdr_t *buf_hdr;

	buf_hdr = odp_buf_to_hdr(buf);

#if defined(MV_NETMAP_BUF_ZERO_COPY) || defined(MV_MUSDK_FREE_BUF_SUPPORT)
	if (buf_hdr->ext_buf_free_cb && (!buf_hdr->ext_buf_free_cb(buf)))
		return;
#endif /* MV_NETMAP_BUF_ZERO_COPY || MV_MUSDK_FREE_BUF_SUPPORT */

	ODP_ASSERT(buf_hdr->allocator != ODP_FREEBUF);
	buf_hdr->allocator = ODP_FREEBUF;

	num = buf_cache->s.num_buf;

	if (odp_likely((num + 1) < POOL_MAX_LOCAL_BUFS)) {
		ret_local_bufs(buf_cache, num, &buf_hdr, 1);
		return;
	}

	pool = get_pool_entry(pool_id);

	num -= POOL_CHUNK_SIZE;
	for (i = 0; i < POOL_CHUNK_SIZE; i++)
		ret_buf(&pool->s, buf_cache->s.buf[num + i]);

	buf_cache->s.num_buf = num;
	ret_local_bufs(buf_cache, num, &buf_hdr, 1);
}

void odp_buffer_free(odp_buffer_t buf)
{
	uint32_t pool_id = pool_id_from_buf(buf);

	buffer_free(pool_id, buf);
}

void odp_buffer_free_multi(const odp_buffer_t buf[], int num)
{
	uint32_t pool_id = pool_id_from_buf(buf[0]);

	buffer_free_multi(pool_id, buf, num);
}

void odp_pool_print(odp_pool_t pool_hdl)
{
	pool_entry_t *pool;
	uint32_t pool_id;

	pool_id = pool_handle_to_index(pool_hdl);
	pool    = get_pool_entry(pool_id);

	uint32_t bufcount  = odp_atomic_load_u32(&pool->s.bufcount);
	uint32_t blkcount  = odp_atomic_load_u32(&pool->s.blkcount);
	uint64_t bufallocs = odp_atomic_load_u64(&pool->s.poolstats.bufallocs);
	uint64_t buffrees  = odp_atomic_load_u64(&pool->s.poolstats.buffrees);
	uint64_t blkallocs = odp_atomic_load_u64(&pool->s.poolstats.blkallocs);
	uint64_t blkfrees  = odp_atomic_load_u64(&pool->s.poolstats.blkfrees);
	uint64_t bufempty  = odp_atomic_load_u64(&pool->s.poolstats.bufempty);
	uint64_t blkempty  = odp_atomic_load_u64(&pool->s.poolstats.blkempty);
	uint64_t bufhiwmct =
		odp_atomic_load_u64(&pool->s.poolstats.buf_high_wm_count);
	uint64_t buflowmct =
		odp_atomic_load_u64(&pool->s.poolstats.buf_low_wm_count);
	uint64_t blkhiwmct =
		odp_atomic_load_u64(&pool->s.poolstats.blk_high_wm_count);
	uint64_t blklowmct =
		odp_atomic_load_u64(&pool->s.poolstats.blk_low_wm_count);

	ODP_DBG("Pool info\n");
	ODP_DBG("---------\n");
	ODP_DBG(" pool            %" PRIu64 "\n",
		odp_pool_to_u64(pool->s.pool_hdl));
	ODP_DBG(" name            %s\n",
		pool->s.flags.has_name ? pool->s.name : "Unnamed Pool");
	ODP_DBG(" pool type       %s\n",
		pool->s.params.type == ODP_POOL_BUFFER ? "buffer" :
	       (pool->s.params.type == ODP_POOL_PACKET ? "packet" :
	       (pool->s.params.type == ODP_POOL_TIMEOUT ? "timeout" :
		"unknown")));
	ODP_DBG(" pool storage    ODP managed shm handle %" PRIu64 "\n",
		odp_shm_to_u64(pool->s.pool_shm));
	ODP_DBG(" pool status     %s\n",
		pool->s.quiesced ? "quiesced" : "active");
	ODP_DBG(" pool opts       %s, %s\n",
		pool->s.flags.unsegmented ? "unsegmented" : "segmented",
		pool->s.flags.predefined  ? "predefined" : "created");
	ODP_DBG(" pool base       %p\n",  pool->s.pool_base_addr);
	ODP_DBG(" pool size       %zu (%zu pages)\n",
		pool->s.pool_size, pool->s.pool_size / ODP_PAGE_SIZE);
	ODP_DBG(" pool mdata base %p\n",  pool->s.pool_mdata_addr);
	ODP_DBG(" udata size      %zu\n", pool->s.udata_size);
	ODP_DBG(" headroom        %u\n",  pool->s.headroom);
	ODP_DBG(" tailroom        %u\n",  pool->s.tailroom);
	if (pool->s.params.type == ODP_POOL_BUFFER) {
		ODP_DBG(" buf size        %zu\n", pool->s.params.buf.size);
		ODP_DBG(" buf align       %u requested, %u used\n",
			pool->s.params.buf.align, pool->s.buf_align);
	} else if (pool->s.params.type == ODP_POOL_PACKET) {
		ODP_DBG(" seg length      %u requested, %u used\n",
			pool->s.params.pkt.seg_len, pool->s.seg_size);
		ODP_DBG(" pkt length      %u requested, %u used\n",
			pool->s.params.pkt.len, pool->s.blk_size);
	}
	ODP_DBG(" num bufs        %u\n",  pool->s.buf_num);
	ODP_DBG(" bufs available  %u %s\n", bufcount,
		pool->s.buf_low_wm_assert ? " **buf low wm asserted**" : "");
	ODP_DBG(" bufs in use     %u\n",  pool->s.buf_num - bufcount);
	ODP_DBG(" buf allocs      %lu\n", bufallocs);
	ODP_DBG(" buf frees       %lu\n", buffrees);
	ODP_DBG(" buf empty       %lu\n", bufempty);
	ODP_DBG(" blk size        %zu\n",
		pool->s.seg_size > ODP_MAX_INLINE_BUF ? pool->s.seg_size : 0);
	ODP_DBG(" blks available  %u %s\n",  blkcount,
		pool->s.blk_low_wm_assert ? " **blk low wm asserted**" : "");
	ODP_DBG(" blk allocs      %lu\n", blkallocs);
	ODP_DBG(" blk frees       %lu\n", blkfrees);
	ODP_DBG(" blk empty       %lu\n", blkempty);
	ODP_DBG(" buf high wm value   %lu\n", pool->s.buf_high_wm);
	ODP_DBG(" buf high wm count   %lu\n", bufhiwmct);
	ODP_DBG(" buf low wm value    %lu\n", pool->s.buf_low_wm);
	ODP_DBG(" buf low wm count    %lu\n", buflowmct);
	ODP_DBG(" blk high wm value   %lu\n", pool->s.blk_high_wm);
	ODP_DBG(" blk high wm count   %lu\n", blkhiwmct);
	ODP_DBG(" blk low wm value    %lu\n", pool->s.blk_low_wm);
	ODP_DBG(" blk low wm count    %lu\n", blklowmct);
}

odp_pool_t odp_buffer_pool(odp_buffer_t buf)
{
	uint32_t pool_id = pool_id_from_buf(buf);

	return pool_index_to_handle(pool_id);
}

void odp_pool_param_init(odp_pool_param_t *params)
{
	memset(params, 0, sizeof(odp_pool_param_t));
}
