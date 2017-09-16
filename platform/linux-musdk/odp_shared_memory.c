/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp/api/shared_memory.h>
#include <odp_internal.h>
#include <odp/api/spinlock.h>
#include <odp/api/align.h>
#include <odp/api/system_info.h>
#include <odp/api/debug.h>
#include <odp_shm_internal.h>
#include <odp_debug_internal.h>
#include <odp_align_internal.h>
#include <odp_config_internal.h>
#include <odp/api/plat/strong_types.h>

#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <asm/mman.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include <env/mv_sys_dma.h>

ODP_STATIC_ASSERT(ODP_CONFIG_SHM_BLOCKS >= ODP_CONFIG_POOLS,
		  "ODP_CONFIG_SHM_BLOCKS < ODP_CONFIG_POOLS");

/* Macro for checking if a number is a power of 2 */
#define POWER_OF_2(_n)	(!((_n) & ((_n) - 1)))
#define NEXT_POWER_OF_2(_num, _new_num) \
do {						\
	if (POWER_OF_2(_num))			\
		_new_num = (_num);		\
	else {					\
		uint64_t tmp = (_num);		\
		_new_num = 1;			\
		while (tmp) {			\
			_new_num <<= 1;		\
			tmp >>= 1;		\
		}				\
	}					\
} while (0)

typedef struct {
	char      name[ODP_SHM_NAME_LEN];
	uint64_t  size;
	uint64_t  align;
	void      *addr_orig;
	void      *addr;
	odp_shm_t hdl;
	uint32_t  flags;
	uint64_t  page_sz;
	int       fd;
} odp_shm_block_t;

typedef struct {
	odp_shm_block_t block[ODP_CONFIG_SHM_BLOCKS];
	odp_spinlock_t  lock;

} odp_shm_table_t;

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* Global shared memory table */
static odp_shm_table_t *odp_shm_tbl;

static inline uint32_t from_handle(odp_shm_t shm)
{
	return _odp_typeval(shm) - 1;
}

static inline odp_shm_t to_handle(uint32_t index)
{
	return _odp_cast_scalar(odp_shm_t, index + 1);
}

static int find_block(const char *name, uint32_t *index)
{
	u32 i;

	for (i = 0; i < ODP_CONFIG_SHM_BLOCKS; i++) {
		if (strcmp(name, odp_shm_tbl->block[i].name) == 0) {
			/* found it */
			if (index != NULL)
				*index = i;

			return 1;
		}
	}

	return 0;
}

int _odp_ishm_init_global(void)
{
	int err;

	odp_shm_tbl = (odp_shm_table_t *)malloc(sizeof(odp_shm_table_t));
	if (!odp_shm_tbl) {
		ODP_ERR("no mem for shm table!\n");
		return -1;
	}
	memset(odp_shm_tbl, 0, sizeof(odp_shm_table_t));
	odp_spinlock_init(&odp_shm_tbl->lock);

	err = mv_sys_dma_mem_init(MUSDK_TOTAL_SHM_SIZE);
	if (err != 0) {
		ODP_ERR("ODP MUSDK DMA-MEM failed (%d)!\n", err);
		free(odp_shm_tbl);
		return err;
	}

	return 0;
}

int _odp_ishm_term_global(void)
{
	mv_sys_dma_mem_destroy();
	free(odp_shm_tbl);
	return 0;
}

int _odp_ishm_init_local(void)
{
	return 0;
}

int _odp_ishm_term_local(void)
{
	return 0;
}

int odp_shm_capability(odp_shm_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_shm_capability_t));

	capa->max_blocks = ODP_CONFIG_SHM_BLOCKS;
	capa->max_size   = 0;
	capa->max_align  = 0;

	return 0;
}

int odp_shm_free(odp_shm_t shm)
{
	u32 i;
	odp_shm_block_t *block;

	if (shm == ODP_SHM_INVALID) {
		ODP_DBG("odp_shm_free: Invalid handle\n");
		return -1;
	}

	i = from_handle(shm);

	if (i >= ODP_CONFIG_SHM_BLOCKS) {
		ODP_DBG("odp_shm_free: Bad handle\n");
		return -1;
	}

	odp_spinlock_lock(&odp_shm_tbl->lock);

	block = &odp_shm_tbl->block[i];

	if (block->addr == NULL) {
		ODP_DBG("odp_shm_free: Free block\n");
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		return 0;
	}

	mv_sys_dma_mem_free(block->addr_orig);

	memset(block, 0, sizeof(odp_shm_block_t));
	odp_spinlock_unlock(&odp_shm_tbl->lock);
	return 0;
}

odp_shm_t odp_shm_reserve(const char *name, uint64_t size, uint64_t align,
			  uint32_t flags ODP_UNUSED)
{
	u32 i;
	odp_shm_block_t *block;

	if (!POWER_OF_2(align)) {
		ODP_DBG("Illegal alignment (%d); round up to next pow-of-2.\n", align);
		NEXT_POWER_OF_2(align, align);
	}

	ODP_DBG("[shm]: %s req: size: %llu, align: %llu, flags: %08x\n", name, size, align, flags);

	odp_spinlock_lock(&odp_shm_tbl->lock);

	if (find_block(name, NULL)) {
		/* Found a block with the same name */
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		ODP_ERR("name \"%s\" already used.\n", name);
		return ODP_SHM_INVALID;
	}

	for (i = 0; i < ODP_CONFIG_SHM_BLOCKS; i++) {
		if (odp_shm_tbl->block[i].addr == NULL) {
			/* Found free block */
			break;
		}
	}

	if (i > ODP_CONFIG_SHM_BLOCKS - 1) {
		/* Table full */
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		ODP_ERR("%s: no more blocks.\n", name);
		return ODP_SHM_INVALID;
	}

	block = &odp_shm_tbl->block[i];

	block->hdl  = to_handle(i);

	strncpy(block->name, name, ODP_SHM_NAME_LEN - 1);
	block->name[ODP_SHM_NAME_LEN - 1] = 0;

	block->addr = mv_sys_dma_mem_alloc(size, align);
	if (!block->addr) {
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		ODP_ERR("%s: allocation failed!\n", name);
		return ODP_SHM_INVALID;
	}

	block->addr_orig  = block->addr;
	block->size       = size;
	block->align      = align;
	block->flags      = flags;
	block->page_sz    = 4096;

	odp_spinlock_unlock(&odp_shm_tbl->lock);

	ODP_DBG("allocated size: %d, align: %d @ %x\n",
		(int)block->size, (int)block->align, (unsigned int)(uintptr_t)block->addr);

	return block->hdl;
}

odp_shm_t odp_shm_lookup(const char *name)
{
	u32 i;
	odp_shm_t hdl;

	odp_spinlock_lock(&odp_shm_tbl->lock);

	if (find_block(name, &i) == 0) {
		odp_spinlock_unlock(&odp_shm_tbl->lock);
		return ODP_SHM_INVALID;
	}

	hdl = odp_shm_tbl->block[i].hdl;
	odp_spinlock_unlock(&odp_shm_tbl->lock);

	return hdl;
}

void *odp_shm_addr(odp_shm_t shm)
{
	u32 i;

	i = from_handle(shm);

	if (i > (ODP_CONFIG_SHM_BLOCKS - 1))
		return NULL;

	return odp_shm_tbl->block[i].addr;
}

int odp_shm_info(odp_shm_t shm, odp_shm_info_t *info)
{
	odp_shm_block_t *block;
	u32 i;

	i = from_handle(shm);

	if (i > (ODP_CONFIG_SHM_BLOCKS - 1))
		return -1;

	block = &odp_shm_tbl->block[i];

	info->name      = block->name;
	info->addr      = block->addr;
	info->size      = block->size;
	info->page_size = block->page_sz;
	info->flags     = block->flags;

	return 0;
}

void odp_shm_print_all(void)
{
	int i;

	ODP_PRINT("\nShared memory\n");
	ODP_PRINT("--------------\n");
	ODP_PRINT("  page size:      %"PRIu64" kB\n",
		  odp_sys_page_size() / 1024);
	ODP_PRINT("  huge page size: %"PRIu64" kB\n",
		  odp_sys_huge_page_size() / 1024);
	ODP_PRINT("\n");

	ODP_PRINT("  id name                       kB align huge addr\n");

	for (i = 0; i < ODP_CONFIG_SHM_BLOCKS; i++) {
		odp_shm_block_t *block;

		block = &odp_shm_tbl->block[i];

		if (block->addr) {
			ODP_PRINT("  %2i %-24s %4"PRIu64"  %4"PRIu64
				  " %p\n",
				  i,
				  block->name,
				  block->size / 1024,
				  block->align,
				  block->addr);
		}
	}

	ODP_PRINT("\n");
}

uint64_t odp_shm_to_u64(odp_shm_t hdl)
{
	return _odp_pri(hdl);
}

