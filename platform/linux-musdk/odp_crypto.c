/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>
#include <odp/api/crypto.h>
#include <odp_internal.h>
#include <odp/api/atomic.h>
#include <odp/api/spinlock.h>
#include <odp/api/sync.h>
#include <odp/api/debug.h>
#include <odp/api/align.h>
#include <odp/api/shared_memory.h>
#include <odp_crypto_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp/api/random.h>
#include <odp_packet_internal.h>

#include <string.h>
#include <stdlib.h>

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#ifdef ODP_PKTIO_MVSAM
#include <drivers/mv_sam.h>

#define MAX_AUTH_BLOCK_SIZE   128 /* Bytes */
#define AUTH_BLOCK_SIZE_64B   64  /* Bytes */
#endif /* ODP_PKTIO_MVSAM */

#define MAX_SESSIONS 32

//#define CHECK_CYCLES
#ifdef CHECK_CYCLES
#include <sys/time.h>   // for gettimeofday()
#define CLK_MHZ	1300
static u64 usecs=0, cnt1=0, cnt2=0, cnt3=0, max_cnt=0;
static struct timeval t0, t1, t2;

#define START_COUNT_CYCLES	\
	gettimeofday(&t1, NULL);
#define STOP_N_REPORT_COUNT_CYCLES(_num,_max)	\
do {						\
	gettimeofday(&t2, NULL);		\
	/* compute and print the elapsed time in millisec */	\
	if (_num) {						\
		usecs += (t2.tv_sec - t1.tv_sec) * 1000000.0;	\
		usecs += (t2.tv_usec - t1.tv_usec);		\
		cnt1+=_num;cnt2++;				\
		if (_num>max_cnt) max_cnt = _num;		\
	} else	cnt3++;						\
	if (cnt1 >= _max) {					\
		u64 tmp = (t2.tv_sec - t0.tv_sec) * 1000000.0;	\
		tmp    += (t2.tv_usec - t0.tv_usec);		\
		printf("Avg cycles: %d (est. perf: %dKpps)\n",	\
			(int)(usecs*CLK_MHZ/cnt1),		\
			(int)((cnt1*1000)/tmp));		\
		printf("Avg burst: %.2f, %d calls for 0 pkts, "	\
			"max was: %d\n", (float)cnt1/cnt2, 	\
			(int)cnt3, (int)max_cnt);		\
		usecs=cnt1=cnt2=cnt3=0;				\
		gettimeofday(&t0, NULL);			\
	}							\
} while (0);

#else
#define START_COUNT_CYCLES
#define STOP_N_REPORT_COUNT_CYCLES(_num,_max)
#endif /* CHECK_CYCLES */

/*
 * Cipher algorithm capabilities
 *
 * Keep sorted: first by key length, then by IV length
 */
static const odp_crypto_cipher_capability_t cipher_capa_null[] = {
{.key_len = 0, .iv_len = 0} };

static const odp_crypto_cipher_capability_t cipher_capa_des[] = {
{.key_len = 24, .iv_len = 8} };

static const odp_crypto_cipher_capability_t cipher_capa_trides_cbc[] = {
{.key_len = 24, .iv_len = 8} };

static const odp_crypto_cipher_capability_t cipher_capa_aes_cbc[] = {
{.key_len = 16, .iv_len = 16} };

static const odp_crypto_cipher_capability_t cipher_capa_aes_gcm[] = {
{.key_len = 16, .iv_len = 12} };

/*
 * Authentication algorithm capabilities
 *
 * Keep sorted: first by digest length, then by key length
 */
static const odp_crypto_auth_capability_t auth_capa_null[] = {
{.digest_len = 0, .key_len = 0, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_md5_hmac[] = {
{.digest_len = 12, .key_len = 16, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 16, .key_len = 16, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_sha1_hmac[] = {
{.digest_len = 12, .key_len = 20, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 20, .key_len = 20, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_sha256_hmac[] = {
{.digest_len = 16, .key_len = 32, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 32, .key_len = 32, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_sha512_hmac[] = {
{.digest_len = 32, .key_len = 64, .aad_len = {.min = 0, .max = 0, .inc = 0} },
{.digest_len = 64, .key_len = 64, .aad_len = {.min = 0, .max = 0, .inc = 0} } };

static const odp_crypto_auth_capability_t auth_capa_aes_gcm[] = {
{.digest_len = 16, .key_len = 0, .aad_len = {.min = 8, .max = 12, .inc = 4} } };

typedef struct odp_crypto_global_s odp_crypto_global_t;

struct odp_crypto_global_s {
	odp_spinlock_t                lock;
	odp_ticketlock_t **openssl_lock;
	odp_crypto_generic_session_t *free;
	odp_crypto_generic_session_t  sessions[0];
};


static odp_crypto_global_t *global;

#ifdef ODP_PKTIO_MVSAM
#define MAX_IV_SIZE		30
#define PROCESS_PKT_BURST_SIZE	32

#define REQ_THRSHLD_LO		(PROCESS_PKT_BURST_SIZE)
#define REQ_THRSHLD_HI		((MVSAM_RING_SIZE<<1)-PROCESS_PKT_BURST_SIZE)
#define IO_ENQ_THRSHLD_LO	(PROCESS_PKT_BURST_SIZE<<1)
#define APP_Q_THRSHLD_HI	(REQ_THRSHLD_HI)

struct crypto_session {

	odp_queue_t     compl_queue;
	odp_pool_t      output_pool;
	char            iv[MAX_IV_SIZE];
	odp_crypto_op_t op;
	struct crypto_cio_info*   cio;
	struct sam_sa  *sa;
};

struct crypto_request {
	struct sam_buf_info sam_src_buf;
	struct sam_buf_info sam_dst_buf;
	odp_crypto_op_result_t	 result;
	struct crypto_session	*session;
	struct crypto_cio_info  *cio;
};

#define MAX_NUM_OF_THREADS            2
#define MAX_NUM_OF_CIO_PER_WORKER     2

static uint8_t	used_cios[MAX_NUM_OF_CIO_PER_WORKER] = {MVSAM_CIOS_RSRV};

static unsigned int         num_session   = 0;
static unsigned int         sam_num_inst  = 1;

#define is_multi_sam()  ((sam_num_inst > 1) ? 1 : 0)


struct crypto_cio_info {
	unsigned int             io_enqs_cnt;
	unsigned int             io_enqs_offs;
	unsigned int             requests_cnt;
	unsigned int             requests_offs;
	struct sam_cio_op_params sam_op_params[MVSAM_RING_SIZE * 2];
	struct crypto_request	 requests[MVSAM_RING_SIZE * 2];
	struct sam_cio           *cio_hw;
};

struct crypto_thread_info
{
	unsigned int             app_enqs_cnt;
	struct crypto_cio_info   cio[2];

};

static struct crypto_thread_info crp_thread[MAX_NUM_OF_THREADS];   /* TODO: add dynamic allocation for this array*/
struct crypto_session            sessions[MVSAM_MAX_NUM_SESSIONS];

#endif /* ODP_PKTIO_MVSAM */

static
odp_crypto_generic_op_result_t *get_op_result_from_event(odp_event_t ev)
{
	odp_packet_hdr_t *hdr = odp_packet_hdr(odp_packet_from_event(ev));
	return &hdr->op_result;
}

#ifdef ODP_PKTIO_MVSAM
static inline struct crypto_cio_info* get_crp_thr_cio(struct crypto_thread_info *crp_thr, odp_crypto_op_t op)
{
	int cio_idx = 0;
	if(is_multi_sam())
		cio_idx = ((op == ODP_CRYPTO_OP_ENCODE)? 0 : 1);

	return &crp_thr->cio[cio_idx];
}

static inline struct crypto_thread_info *get_crp_thread(void)
{
	int thr_id = odp_thread_id() - 1;
	if(odp_unlikely(thr_id > MAX_NUM_OF_THREADS)) {
		ODP_ERR("invalid thread id. thr_id=%d!\n", thr_id);
		return NULL;
	}

	return &crp_thread[thr_id];
}

static int find_free_cio(int cio_local_idx)
{
	int	i;

	for (i = 0; i < MVSAM_TOTAL_NUM_CIOS; i++) {
		if (!((uint64_t)(1 << i) & used_cios[cio_local_idx])) {
			used_cios[cio_local_idx] |= (uint64_t)(1 << i);
			break;
		}
	}
	if (i == MVSAM_TOTAL_NUM_CIOS) {
		ODP_ERR("no free CIO found!\n");
		return -ENOSPC;
	}
	return i;
}

static enum sam_auth_alg mvsam_get_auth_alg(
							odp_auth_alg_t auth_alg,
							int *icv_len)
{
	*icv_len = 0;
	switch(auth_alg)
	{
	case ODP_AUTH_ALG_NULL:
		return SAM_AUTH_NONE;
	case ODP_AUTH_ALG_MD5_HMAC:
		*icv_len = 12;
		return SAM_AUTH_HMAC_MD5;
	case ODP_AUTH_ALG_SHA256_HMAC:
		*icv_len = 16;
		return SAM_AUTH_HMAC_SHA2_256;
	case ODP_AUTH_ALG_AES_GCM:
		*icv_len = 16;
		return SAM_AUTH_AES_GCM;
	default:
		return SAM_AUTH_NONE;
	}
}

static int mvsam_odp_crypto_capability(odp_crypto_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_crypto_capability_t));
	capa->ciphers.bit.null = 1;
	capa->ciphers.bit.des = 1;
	capa->ciphers.bit.trides_cbc  = 1;
	capa->ciphers.bit.aes_cbc  = 1;
	capa->ciphers.bit.aes_gcm  = 1;
	capa->auths.bit.null = 1;
	capa->auths.bit.md5_hmac = 1;
	capa->auths.bit.sha256_hmac = 1;
	capa->auths.bit.aes_gcm  = 1;
	capa->max_sessions = 20;
	return 0;
}

static int mvsam_set_session_params(
				struct sam_session_params *sam_session,
				odp_crypto_session_param_t *params)
{
	int icv_len;

	sam_session->auth_alg = mvsam_get_auth_alg(params->auth_alg, &icv_len);
	sam_session->proto          = SAM_PROTO_NONE;
	sam_session->dir            = params->op;
	sam_session->cipher_mode    = SAM_CIPHER_CBC;

	switch (params->cipher_alg) {
	case ODP_CIPHER_ALG_DES:
		sam_session->cipher_alg = SAM_CIPHER_DES;
		break;
	case ODP_CIPHER_ALG_3DES_CBC:
		sam_session->cipher_alg = SAM_CIPHER_3DES;
		break;
	case ODP_CIPHER_ALG_AES_CBC:
		sam_session->cipher_alg = SAM_CIPHER_AES;
		break;
	case ODP_CIPHER_ALG_AES_GCM:
		sam_session->cipher_alg  = SAM_CIPHER_AES;
		sam_session->cipher_mode = SAM_CIPHER_GCM;
		break;
	default:
		return -1;
	}

	sam_session->cipher_iv      = params->iv.data;
	sam_session->cipher_key     = params->cipher_key.data;
	sam_session->cipher_key_len = params->cipher_key.length;
	sam_session->auth_key       = params->auth_key.data;
	sam_session->auth_key_len   = params->auth_key.length;
	sam_session->u.basic.auth_aad_len = icv_len;
	return 0;
}

static int mvsam_odp_crypto_session_create(
	odp_crypto_session_param_t *params,
	odp_crypto_session_t *session_out,
	odp_crypto_ses_create_err_t *status)
{
	struct sam_session_params sam_session;
	struct sam_sa *sa = NULL;
	int           rc;

	/* check we aren't pass the maximum number of sessions*/
	if (odp_unlikely(num_session) == MVSAM_MAX_NUM_SESSIONS) {
		ODP_ERR("reach maximum sessions. failed to create a new session!\n");
		*status = -1;
		return -1;
	}
	memset(&sam_session, 0, sizeof(sam_session));
	rc = mvsam_set_session_params(&sam_session, params);
	if (odp_unlikely(rc != 0)) {
		ODP_ERR("invalid session params. failed to create a new session!\n");
		*status = -1;
		return -1;
	}

	rc = sam_session_create(&sam_session, &sa);
	if(odp_unlikely(rc)) {
		ODP_ERR("error while create new session\n");
		*status = -1;
		return -1;
	}
	ODP_DBG("crypto: session (%d) created\n", num_session);
	sessions[num_session].compl_queue   = params->compl_queue;
	sessions[num_session].output_pool   = params->output_pool;
	sessions[num_session].op            = params->op;
	sessions[num_session].sa            = sa;
	memcpy(sessions[num_session].iv, sam_session.cipher_iv, MAX_IV_SIZE);
	*session_out = (odp_crypto_session_t)&sessions[num_session++];
	*status = 0;
	ODP_DBG("crypto: session-%d has created\n", num_session);
	return rc;
}

static int mvsam_odp_crypto_session_destroy(odp_crypto_session_t session)
{
	int rc;
	struct crypto_session *crp_session;
	crp_session = (struct crypto_session *)session;
	rc = sam_session_destroy(crp_session->sa);
	if(odp_unlikely(rc)) {
		ODP_ERR("error while destroy session\n");
		return rc;
	}
	return 0;
}

static inline int mvsam_result_enq(struct sam_cio_op_result *sam_res, int num_res)
{
	odp_event_t			 completion_events[MVSAM_RING_SIZE];
	odp_crypto_generic_op_result_t	*op_result;
	odp_queue_t			 compl_queue = NULL;
	struct crypto_thread_info *crp_thr;
	struct crypto_cio_info    *cio;
	struct crypto_request     *result = NULL;
	int			               i;

	crp_thr       = get_crp_thread();
	if(odp_unlikely(crp_thr == NULL))
		return -1;

	for (i=0; i<num_res; i++) {
		result = (struct crypto_request *)sam_res[i].cookie;
		compl_queue = result->session->compl_queue;

		completion_events[i] = odp_packet_to_event(result->result.pkt);
		_odp_buffer_event_type_set(odp_buffer_from_event(completion_events[i]),
					ODP_EVENT_CRYPTO_COMPL);

		/* Asynchronous, build result (no HW so no errors) and send it*/
		op_result = get_op_result_from_event(completion_events[i]);

		op_result->magic  = OP_RESULT_MAGIC;
		op_result->result.ctx = result->result.ctx;
		op_result->result.pkt = result->result.pkt;
		/* TODO: fill in correct result! */
		op_result->result.ok                    = (sam_res[i].status == SAM_CIO_OK) ? 1 : 0;
		if (odp_queue_enq(compl_queue, completion_events[i]) < 0) {
			ODP_ERR("Failed to enQ to app Q!\n");
			return -1;
		}
	}

/*
	if (odp_queue_enq_multi(compl_queue, completion_events, num_res) < 0) {
		ODP_ERR("Failed to enQ to app Q!\n");
		return -1;
	}
*/
	if(num_res > 0) {
		if(odp_unlikely(!result)) {
			ODP_ERR("invalid result!\n");
			return -1;
		}

		cio = result->cio;
		cio->io_enqs_cnt -= num_res;
		crp_thr->app_enqs_cnt += num_res;
	}
	return 0;
}

static int mvsam_odp_crypto_operation(odp_crypto_op_param_t *params,
				      odp_bool_t *posted,
				      odp_crypto_op_result_t *result)
{
	struct crypto_session	  *session;
	struct crypto_thread_info *crp_thr;
	struct crypto_cio_info    *cio;
	struct sam_cio_op_result sam_res_params[MVSAM_RING_SIZE];
	u16			 num_reqs;
	int			 rc = 0, flush_io_qs = 0;
	unsigned int tmp_offs, requests_offs, i;
	NOTUSED(result);
	crp_thr       = get_crp_thread();
	if(odp_unlikely(crp_thr == NULL))
		return -1;


	/* TODO: temporary W/A for immediate flushing of the SAM IO Qs
	 * until we support it correctly by timeouts */
	if (!params)
		flush_io_qs = 1;

	if (crp_thr->app_enqs_cnt >= APP_Q_THRSHLD_HI && !flush_io_qs) {
		ODP_DBG("App Q is full (%d)!\n", crp_thr->app_enqs_cnt);
		*posted = 0;
		result->ok = 0;
		return 0;
	}

	for(i = 0 ; i < sam_num_inst ; i++) {
		cio = &crp_thr->cio[i];

		/* If we reach to the end of the ring, we need to "drain" it a little */
		if ((flush_io_qs && cio->io_enqs_cnt) ||
			(cio->io_enqs_cnt >= IO_ENQ_THRSHLD_LO)) {
			num_reqs = PROCESS_PKT_BURST_SIZE;
			rc = sam_cio_deq(cio->cio_hw, sam_res_params, &num_reqs);
			if(odp_unlikely(rc)) {
				ODP_ERR("odp_musdk: failed to dequeue request\n");
			/* TODO: drop all err pkts! */
				return rc;
			}
			/* Enqueue to app Q */
			rc = mvsam_result_enq(sam_res_params, num_reqs);
			if (odp_unlikely(rc))
				return rc;
		}
		if ((flush_io_qs && cio->requests_cnt) ||
			(cio->requests_cnt >= REQ_THRSHLD_LO)) {
			num_reqs = PROCESS_PKT_BURST_SIZE;
			if ((cio->io_enqs_offs > cio->requests_offs) &&
				((REQ_THRSHLD_HI - cio->io_enqs_offs) < PROCESS_PKT_BURST_SIZE))
				num_reqs = (REQ_THRSHLD_HI - cio->io_enqs_offs);
			else if ((cio->io_enqs_offs <= cio->requests_offs) &&
					 ((cio->requests_offs - cio->io_enqs_offs) < PROCESS_PKT_BURST_SIZE))
				num_reqs = (cio->requests_offs - cio->io_enqs_offs);
			rc = sam_cio_enq(cio->cio_hw, &cio->sam_op_params[cio->io_enqs_offs], &num_reqs);
			if(odp_unlikely(rc)) {
				ODP_ERR("odp_musdk: failed to enqueue %d requests (%d)!\n",
				cio->requests_cnt, rc);
				/* TODO: drop all err pkts! */
				return rc;
			}
			cio->requests_cnt -= num_reqs;
			cio->io_enqs_cnt  += num_reqs;
			cio->io_enqs_offs += num_reqs;
			if (cio->io_enqs_offs == REQ_THRSHLD_HI)
				cio->io_enqs_offs = 0;
		}
	}

	if (flush_io_qs)
		return 0;

	session  = (struct crypto_session *)params->session;
	cio = get_crp_thr_cio(crp_thr, session->op);
	requests_offs = cio->requests_offs;

	tmp_offs = requests_offs + 1;
	if (tmp_offs == REQ_THRSHLD_HI)
		tmp_offs = 0;
	if (tmp_offs == cio->io_enqs_offs) {
		ODP_DBG("Requests ring is full (%d)!\n", cio->requests_cnt);
		*posted = 0;
		result->ok = 0;
		return 0;
	}

	cio->sam_op_params[requests_offs].cipher_len    = params->cipher_range.length;
	cio->sam_op_params[requests_offs].cipher_offset = params->cipher_range.offset;

	cio->sam_op_params[requests_offs].cookie        = &cio->requests[requests_offs];
	cio->sam_op_params[requests_offs].sa            = session->sa;
	cio->requests[requests_offs].sam_src_buf.len    = odp_packet_len(params->pkt);

	cio->requests[requests_offs].sam_src_buf.vaddr = odp_packet_data(params->pkt);
	cio->requests[requests_offs].sam_src_buf.paddr =
		mv_sys_dma_mem_virt2phys((void *)((uintptr_t)odp_packet_data(params->pkt)));

	/* TODO: need to get the real buffer size from the odp_buffer structure. */
	cio->requests[requests_offs].sam_dst_buf.len   = odp_packet_len(params->pkt) + 64;
		/*odp_packet_headroom(params->pkt) + odp_packet_len(params->pkt) + 64;*/

	cio->requests[requests_offs].sam_dst_buf.vaddr = odp_packet_data(params->out_pkt);
	cio->requests[requests_offs].sam_dst_buf.paddr =
		mv_sys_dma_mem_virt2phys((void *)((uintptr_t)odp_packet_data(params->out_pkt)));

	cio->sam_op_params[requests_offs].src = &cio->requests[requests_offs].sam_src_buf;
	cio->sam_op_params[requests_offs].dst = &cio->requests[requests_offs].sam_dst_buf;
	cio->sam_op_params[requests_offs].auth_len    = params->auth_range.length;

	cio->sam_op_params[requests_offs].auth_offset = params->auth_range.offset;
	cio->sam_op_params[requests_offs].num_bufs    = 1;

	if (params->override_iv_ptr != 0)
		cio->sam_op_params[requests_offs].cipher_iv = params->override_iv_ptr;
	else
		cio->sam_op_params[requests_offs].cipher_iv = (u8 *)session->iv;

	cio->requests[requests_offs].result.ctx = params->ctx;
	cio->requests[requests_offs].result.pkt = params->out_pkt;
	cio->requests[requests_offs].session    = session;
	cio->requests[requests_offs].cio        = cio;

	cio->requests_offs++;
	if (cio->requests_offs == REQ_THRSHLD_HI)
		cio->requests_offs = 0;
	cio->requests_cnt++;
	/* Indicate to caller operation was async, */
	/* no packet received from device          */
	*posted = 1;

	return 0;
}

static int mvsam_odp_crypto_init_cio(int num_of_threads, int num_local_cios)
{
	struct sam_cio_params  cio_params;
	struct sam_init_params init_params;
	int cio_id, err = 0, i, cio_local_idx;
	char name[15];

	memset(name, 0, sizeof(name));
	memset(&cio_params, 0, sizeof(cio_params));
	cio_params.match = name;
	cio_params.size = MVSAM_RING_SIZE;
	init_params.max_num_sessions = MVSAM_MAX_NUM_SESSIONS;

	sam_init(&init_params);
	for(i = 0 ; i < num_of_threads ; i++) {
		for(cio_local_idx = 0 ; cio_local_idx < num_local_cios ; cio_local_idx++) {
			cio_id = find_free_cio(cio_local_idx);
			if (cio_id < 0) {
				ODP_ERR("free CIO not found!\n");
				return cio_id;
			}
			snprintf(name, sizeof(name), "cio-%d:%d", cio_local_idx, cio_id);
			ODP_PRINT("found cio: %s\n", name);
			err = sam_cio_init(&cio_params, &crp_thread[i].cio[cio_local_idx].cio_hw);

			if (err != 0)
				return err;
			if (!crp_thread[i].cio[cio_local_idx].cio_hw) {
				ODP_ERR("CIO init failed. cio %d local_cio %d!\n", i, cio_local_idx, i);
				return -1;
			}
		}
	}
	return err;
}

static int mvsam_odp_crypto_init_global(void)
{
	int		err, i;

	sam_num_inst = sam_get_num_inst();
	err = mvsam_odp_crypto_init_cio(MAX_NUM_OF_THREADS, sam_num_inst);
	ODP_DBG("crypto: allocate crp_op_request - %d\n", MVSAM_RING_SIZE);

	for(i = 0 ; i < MAX_NUM_OF_THREADS ; i++) {
		memset(crp_thread[i].cio[0].sam_op_params, 0, sizeof(struct sam_cio_op_params));
		memset(crp_thread[i].cio[1].sam_op_params, 0, sizeof(struct sam_cio_op_params));
	}
	return err;
}

static int mvsam_odp_crypto_term_global(void)
{
	unsigned int i, cio_local_idx;

	for (i = 0 ; i < num_session ; i++)
		sam_session_destroy(sessions[i].sa);

	for(i = 0 ; i < MAX_NUM_OF_THREADS ; i++) {
		for(cio_local_idx = 0 ; cio_local_idx < sam_num_inst ; cio_local_idx++)
			sam_cio_deinit(crp_thread[i].cio[cio_local_idx].cio_hw);
	}
	sam_deinit();
	return 0;
}
#endif /* ODP_PKTIO_MVSAM */

static
odp_crypto_generic_session_t *alloc_session(void)
{
	odp_crypto_generic_session_t *session = NULL;

	odp_spinlock_lock(&global->lock);
	session = global->free;
	if (session) {
		global->free = session->next;
		session->next = NULL;
	}
	odp_spinlock_unlock(&global->lock);

	return session;
}

static
void free_session(odp_crypto_generic_session_t *session)
{
	odp_spinlock_lock(&global->lock);
	session->next = global->free;
	global->free = session;
	odp_spinlock_unlock(&global->lock);
}

static odp_crypto_alg_err_t
null_crypto_routine(odp_crypto_op_param_t *param ODP_UNUSED,
		    odp_crypto_generic_session_t *session ODP_UNUSED)
{
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
void packet_hmac(odp_crypto_op_param_t *param,
		 odp_crypto_generic_session_t *session,
		 uint8_t *hash)
{
	odp_packet_t pkt = param->out_pkt;
	uint32_t offset = param->auth_range.offset;
	uint32_t len   = param->auth_range.length;
	HMAC_CTX ctx;

	ODP_ASSERT(offset + len <= odp_packet_len(pkt));

	/* Hash it */
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx,
		     session->auth.key,
		     session->auth.key_length,
		     session->auth.evp_md,
		     NULL);

	while (len > 0) {
		uint32_t seglen = 0; /* GCC */
		void *mapaddr = odp_packet_offset(pkt, offset, &seglen, NULL);
		uint32_t maclen = len > seglen ? seglen : len;

		HMAC_Update(&ctx, mapaddr, maclen);
		offset  += maclen;
		len     -= maclen;
	}

	HMAC_Final(&ctx, hash, NULL);
	HMAC_CTX_cleanup(&ctx);
}

static
odp_crypto_alg_err_t auth_gen(odp_crypto_op_param_t *param,
			      odp_crypto_generic_session_t *session)
{
	uint8_t  hash[EVP_MAX_MD_SIZE];

	/* Hash it */
	packet_hmac(param, session, hash);

	/* Copy to the output location */
	odp_packet_copy_from_mem(param->out_pkt,
				 param->hash_result_offset,
				 session->auth.bytes,
				 hash);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t auth_check(odp_crypto_op_param_t *param,
				odp_crypto_generic_session_t *session)
{
	uint32_t bytes = session->auth.bytes;
	uint8_t  hash_in[EVP_MAX_MD_SIZE];
	uint8_t  hash_out[EVP_MAX_MD_SIZE];

	/* Copy current value out and clear it before authentication */
	odp_packet_copy_to_mem(param->out_pkt, param->hash_result_offset,
			       bytes, hash_in);

	_odp_packet_set_data(param->out_pkt, param->hash_result_offset,
			     0, bytes);

	/* Hash it */
	packet_hmac(param, session, hash_out);

	/* Verify match */
	if (0 != memcmp(hash_in, hash_out, bytes))
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	/* Matched */
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
int internal_encrypt(EVP_CIPHER_CTX *ctx, odp_crypto_op_param_t *param)
{
	odp_packet_t pkt = param->out_pkt;
	unsigned in_pos = param->cipher_range.offset;
	unsigned out_pos = param->cipher_range.offset;
	unsigned in_len = param->cipher_range.length;
	uint8_t block[2 * EVP_MAX_BLOCK_LENGTH];
	unsigned block_len = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx));
	int cipher_len;
	int ret;

	while (in_len > 0) {
		uint32_t seglen = 0; /* GCC */
		uint8_t *insegaddr = odp_packet_offset(pkt, in_pos,
						       &seglen, NULL);
		unsigned inseglen = in_len < seglen ? in_len : seglen;

		/* There should be at least 1 additional block in out buffer */
		if (inseglen > block_len) {
			unsigned part = inseglen - block_len;

			EVP_EncryptUpdate(ctx, insegaddr, &cipher_len,
					  insegaddr, part);
			in_pos += part;
			in_len -= part;
			insegaddr += part;
			inseglen -= part;

			out_pos += cipher_len;
		}

		/* Use temporal storage */
		if (inseglen > 0) {
			unsigned part = inseglen;

			EVP_EncryptUpdate(ctx, block, &cipher_len,
					  insegaddr, part);
			in_pos += part;
			in_len -= part;
			insegaddr += part;
			inseglen -= part;

			odp_packet_copy_from_mem(pkt, out_pos,
						 cipher_len, block);
			out_pos += cipher_len;
		}
	}

	ret = EVP_EncryptFinal_ex(ctx, block, &cipher_len);
	odp_packet_copy_from_mem(pkt, out_pos, cipher_len, block);

	return ret;
}

static
int internal_decrypt(EVP_CIPHER_CTX *ctx, odp_crypto_op_param_t *param)
{
	odp_packet_t pkt = param->out_pkt;
	unsigned in_pos = param->cipher_range.offset;
	unsigned out_pos = param->cipher_range.offset;
	unsigned in_len = param->cipher_range.length;
	uint8_t block[2 * EVP_MAX_BLOCK_LENGTH];
	unsigned block_len = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx));
	int cipher_len;
	int ret;

	while (in_len > 0) {
		uint32_t seglen = 0; /* GCC */
		uint8_t *insegaddr = odp_packet_offset(pkt, in_pos,
						       &seglen, NULL);
		unsigned inseglen = in_len < seglen ? in_len : seglen;

		/* There should be at least 1 additional block in out buffer */
		if (inseglen > block_len) {
			unsigned part = inseglen - block_len;

			EVP_DecryptUpdate(ctx, insegaddr, &cipher_len,
					  insegaddr, part);
			in_pos += part;
			in_len -= part;
			insegaddr += part;
			inseglen -= part;

			out_pos += cipher_len;
		}

		/* Use temporal storage */
		if (inseglen > 0) {
			unsigned part = inseglen;

			EVP_DecryptUpdate(ctx, block, &cipher_len,
					  insegaddr, part);
			in_pos += part;
			in_len -= part;
			insegaddr += part;
			inseglen -= part;

			odp_packet_copy_from_mem(pkt, out_pos,
						 cipher_len, block);
			out_pos += cipher_len;
		}
	}

	ret = EVP_DecryptFinal_ex(ctx, block, &cipher_len);
	odp_packet_copy_from_mem(pkt, out_pos, cipher_len, block);

	return ret;
}

static
odp_crypto_alg_err_t cipher_encrypt(odp_crypto_op_param_t *param,
				    odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx;
	void *iv_ptr;
	int ret;

	if (param->override_iv_ptr)
		iv_ptr = param->override_iv_ptr;
	else if (session->p.iv.data)
		iv_ptr = session->cipher.iv_data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/* Encrypt it */
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, session->cipher.evp_cipher, NULL,
			   session->cipher.key_data, NULL);
	EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv_ptr);
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	ret = internal_encrypt(ctx, param);

	EVP_CIPHER_CTX_free(ctx);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_DATA_SIZE :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t cipher_decrypt(odp_crypto_op_param_t *param,
				    odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx;
	void *iv_ptr;
	int ret;

	if (param->override_iv_ptr)
		iv_ptr = param->override_iv_ptr;
	else if (session->p.iv.data)
		iv_ptr = session->cipher.iv_data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/* Decrypt it */
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, session->cipher.evp_cipher, NULL,
			   session->cipher.key_data, NULL);
	EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv_ptr);
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	ret = internal_decrypt(ctx, param);

	EVP_CIPHER_CTX_free(ctx);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_DATA_SIZE :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static int process_cipher_param(odp_crypto_generic_session_t *session,
				const EVP_CIPHER *cipher)
{
	/* Verify Key len is valid */
	if ((uint32_t)EVP_CIPHER_key_length(cipher) !=
	    session->p.cipher_key.length)
		return -1;

	/* Verify IV len is correct */
	if (!((0 == session->p.iv.length) ||
	      ((uint32_t)EVP_CIPHER_iv_length(cipher) == session->p.iv.length)))
		return -1;

	session->cipher.evp_cipher = cipher;

	memcpy(session->cipher.key_data, session->p.cipher_key.data,
	       session->p.cipher_key.length);

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op)
		session->cipher.func = cipher_encrypt;
	else
		session->cipher.func = cipher_decrypt;

	return 0;
}

static
odp_crypto_alg_err_t aes_gcm_encrypt(odp_crypto_op_param_t *param,
				     odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx;
	const uint8_t *aad_head = param->aad.ptr;
	uint32_t aad_len = param->aad.length;
	void *iv_ptr;
	int dummy_len = 0;
	uint8_t block[EVP_MAX_MD_SIZE];
	int ret;

	if (param->override_iv_ptr)
		iv_ptr = param->override_iv_ptr;
	else if (session->p.iv.data)
		iv_ptr = session->cipher.iv_data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/* Encrypt it */
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, session->cipher.evp_cipher, NULL,
			   session->cipher.key_data, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
			    session->p.iv.length, NULL);
	EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv_ptr);
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	/* Authenticate header data (if any) without encrypting them */
	if (aad_len > 0)
		EVP_EncryptUpdate(ctx, NULL, &dummy_len,
				  aad_head, aad_len);

	ret = internal_encrypt(ctx, param);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
			    session->p.auth_digest_len, block);
	odp_packet_copy_from_mem(param->out_pkt, param->hash_result_offset,
				 session->p.auth_digest_len, block);

	EVP_CIPHER_CTX_free(ctx);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_DATA_SIZE :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t aes_gcm_decrypt(odp_crypto_op_param_t *param,
				     odp_crypto_generic_session_t *session)
{
	EVP_CIPHER_CTX *ctx;
	const uint8_t *aad_head = param->aad.ptr;
	uint32_t aad_len = param->aad.length;
	int dummy_len = 0;
	void *iv_ptr;
	uint8_t block[EVP_MAX_MD_SIZE];
	int ret;

	if (param->override_iv_ptr)
		iv_ptr = param->override_iv_ptr;
	else if (session->p.iv.data)
		iv_ptr = session->cipher.iv_data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/* Decrypt it */
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, session->cipher.evp_cipher, NULL,
			   session->cipher.key_data, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
			    session->p.iv.length, NULL);
	EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv_ptr);
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	odp_packet_copy_to_mem(param->out_pkt, param->hash_result_offset,
			       session->p.auth_digest_len, block);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
			    session->p.auth_digest_len, block);

	/* Authenticate header data (if any) without encrypting them */
	if (aad_len > 0)
		EVP_DecryptUpdate(ctx, NULL, &dummy_len,
				  aad_head, aad_len);

	ret = internal_decrypt(ctx, param);

	EVP_CIPHER_CTX_free(ctx);

	return ret <= 0 ? ODP_CRYPTO_ALG_ERR_ICV_CHECK :
			  ODP_CRYPTO_ALG_ERR_NONE;
}

static int process_aes_gcm_param(odp_crypto_generic_session_t *session,
				 const EVP_CIPHER *cipher)
{
	/* Verify Key len is valid */
	if ((uint32_t)EVP_CIPHER_key_length(cipher) !=
	    session->p.cipher_key.length)
		return -1;

	memcpy(session->cipher.key_data, session->p.cipher_key.data,
	       session->p.cipher_key.length);

	session->cipher.evp_cipher = cipher;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op)
		session->cipher.func = aes_gcm_encrypt;
	else
		session->cipher.func = aes_gcm_decrypt;

	return 0;
}

static int process_auth_param(odp_crypto_generic_session_t *session,
			      uint32_t key_length,
			      const EVP_MD *evp_md)
{
	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == session->p.op)
		session->auth.func = auth_gen;
	else
		session->auth.func = auth_check;

	session->auth.evp_md = evp_md;

	/* Number of valid bytes */
	session->auth.bytes = session->p.auth_digest_len;
	if (session->auth.bytes < (unsigned)EVP_MD_size(evp_md) / 2)
		return -1;

	/* Convert keys */
	session->auth.key_length = key_length;
	memcpy(session->auth.key, session->p.auth_key.data,
	       session->auth.key_length);

	return 0;
}

int odp_crypto_capability(odp_crypto_capability_t *capa)
{
	if (NULL == capa)
		return -1;

#ifdef ODP_PKTIO_MVSAM
	return mvsam_odp_crypto_capability(capa);
#endif /* ODP_PKTIO_MVSAM */

	/* Initialize crypto capability structure */
	memset(capa, 0, sizeof(odp_crypto_capability_t));

	capa->ciphers.bit.null       = 1;
	capa->ciphers.bit.des        = 1;
	capa->ciphers.bit.trides_cbc = 1;
	capa->ciphers.bit.aes_cbc    = 1;
	capa->ciphers.bit.aes_gcm    = 1;

	capa->auths.bit.null         = 1;
	capa->auths.bit.md5_hmac     = 1;
	capa->auths.bit.sha1_hmac    = 1;
	capa->auths.bit.sha256_hmac  = 1;
	capa->auths.bit.sha512_hmac  = 1;
	capa->auths.bit.aes_gcm      = 1;

#if ODP_DEPRECATED_API
	capa->ciphers.bit.aes128_cbc = 1;
	capa->ciphers.bit.aes128_gcm = 1;
	capa->auths.bit.md5_96       = 1;
	capa->auths.bit.sha256_128   = 1;
	capa->auths.bit.aes128_gcm   = 1;
#endif

	capa->max_sessions = MAX_SESSIONS;

	return 0;
}

int odp_crypto_cipher_capability(odp_cipher_alg_t cipher,
				 odp_crypto_cipher_capability_t dst[],
				 int num_copy)
{
	const odp_crypto_cipher_capability_t *src;
	int num;
	int size = sizeof(odp_crypto_cipher_capability_t);

	switch (cipher) {
	case ODP_CIPHER_ALG_NULL:
		src = cipher_capa_null;
		num = sizeof(cipher_capa_null) / size;
		break;
	case ODP_CIPHER_ALG_DES:
		src = cipher_capa_des;
		num = sizeof(cipher_capa_des) / size;
		break;
	case ODP_CIPHER_ALG_3DES_CBC:
		src = cipher_capa_trides_cbc;
		num = sizeof(cipher_capa_trides_cbc) / size;
		break;
	case ODP_CIPHER_ALG_AES_CBC:
		src = cipher_capa_aes_cbc;
		num = sizeof(cipher_capa_aes_cbc) / size;
		break;
	case ODP_CIPHER_ALG_AES_GCM:
		src = cipher_capa_aes_gcm;
		num = sizeof(cipher_capa_aes_gcm) / size;
		break;
	default:
		return -1;
	}

	if (num < num_copy)
		num_copy = num;

	memcpy(dst, src, num_copy * size);

	return num;
}

int odp_crypto_auth_capability(odp_auth_alg_t auth,
			       odp_crypto_auth_capability_t dst[], int num_copy)
{
	const odp_crypto_auth_capability_t *src;
	int num;
	int size = sizeof(odp_crypto_auth_capability_t);

	switch (auth) {
	case ODP_AUTH_ALG_NULL:
		src = auth_capa_null;
		num = sizeof(auth_capa_null) / size;
		break;
	case ODP_AUTH_ALG_MD5_HMAC:
		src = auth_capa_md5_hmac;
		num = sizeof(auth_capa_md5_hmac) / size;
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		src = auth_capa_sha1_hmac;
		num = sizeof(auth_capa_sha1_hmac) / size;
		break;
	case ODP_AUTH_ALG_SHA256_HMAC:
		src = auth_capa_sha256_hmac;
		num = sizeof(auth_capa_sha256_hmac) / size;
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		src = auth_capa_sha512_hmac;
		num = sizeof(auth_capa_sha512_hmac) / size;
		break;
	case ODP_AUTH_ALG_AES_GCM:
		src = auth_capa_aes_gcm;
		num = sizeof(auth_capa_aes_gcm) / size;
		break;
	default:
		return -1;
	}

	if (num < num_copy)
		num_copy = num;

	memcpy(dst, src, num_copy * size);

	return num;
}

int
odp_crypto_session_create(odp_crypto_session_param_t *param,
			  odp_crypto_session_t *session_out,
			  odp_crypto_ses_create_err_t *status)
{
	int rc;
	odp_crypto_generic_session_t *session;
	int aes_gcm = 0;
	
#ifdef ODP_PKTIO_MVSAM
	return mvsam_odp_crypto_session_create(param, session_out, status);
#endif /* ODP_PKTIO_MVSAM */

	/* Default to successful result */
	*status = ODP_CRYPTO_SES_CREATE_ERR_NONE;

	/* Allocate memory for this session */
	session = alloc_session();
	if (NULL == session) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_ENOMEM;
		return -1;
	}

	/* Copy parameters */
	session->p = *param;

	if (session->p.iv.length > MAX_IV_LEN) {
		ODP_DBG("Maximum IV length exceeded\n");
		free_session(session);
		return -1;
	}

	/* Copy IV data */
	if (session->p.iv.data)
		memcpy(session->cipher.iv_data, session->p.iv.data,
		       session->p.iv.length);

	/* Derive order */
	if (ODP_CRYPTO_OP_ENCODE == param->op)
		session->do_cipher_first =  param->auth_cipher_text;
	else
		session->do_cipher_first = !param->auth_cipher_text;

	/* Process based on cipher */
	switch (param->cipher_alg) {
	case ODP_CIPHER_ALG_NULL:
		session->cipher.func = null_crypto_routine;
		rc = 0;
		break;
	case ODP_CIPHER_ALG_DES:
	case ODP_CIPHER_ALG_3DES_CBC:
		rc = process_cipher_param(session, EVP_des_ede3_cbc());
		break;
	case ODP_CIPHER_ALG_AES_CBC:
		rc = process_cipher_param(session, EVP_aes_128_cbc());
		break;
#if ODP_DEPRECATED_API
	case ODP_CIPHER_ALG_AES128_GCM:
		if (param->auth_alg == ODP_AUTH_ALG_AES128_GCM)
			aes_gcm = 1;
		/* Fallthrough */
#endif
	case ODP_CIPHER_ALG_AES_GCM:
		/* AES-GCM requires to do both auth and
		 * cipher at the same time */
		if (param->auth_alg == ODP_AUTH_ALG_AES_GCM || aes_gcm)
			rc = process_aes_gcm_param(session, EVP_aes_128_gcm());
		else
			rc = -1;
		break;
	default:
		rc = -1;
	}

	/* Check result */
	if (rc) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER;
		free_session(session);
		return -1;
	}

	aes_gcm = 0;

	/* Process based on auth */
	switch (param->auth_alg) {
	case ODP_AUTH_ALG_NULL:
		session->auth.func = null_crypto_routine;
		rc = 0;
		break;
#if ODP_DEPRECATED_API
	case ODP_AUTH_ALG_MD5_96:
		/* Fixed digest tag length with deprecated algo */
		session->p.auth_digest_len = 96 / 8;
		/* Fallthrough */
#endif
	case ODP_AUTH_ALG_MD5_HMAC:
		rc = process_auth_param(session, 16, EVP_md5());
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		rc = process_auth_param(session, 20, EVP_sha1());
		break;
#if ODP_DEPRECATED_API
	case ODP_AUTH_ALG_SHA256_128:
		/* Fixed digest tag length with deprecated algo */
		session->p.auth_digest_len = 128 / 8;
		/* Fallthrough */
#endif
	case ODP_AUTH_ALG_SHA256_HMAC:
		rc = process_auth_param(session, 32, EVP_sha256());
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		rc = process_auth_param(session, 64, EVP_sha512());
		break;
#if ODP_DEPRECATED_API
	case ODP_AUTH_ALG_AES128_GCM:
		if (param->cipher_alg == ODP_CIPHER_ALG_AES128_GCM)
			aes_gcm = 1;
		/* Fixed digest tag length with deprecated algo */
		session->p.auth_digest_len = 16;
		/* Fallthrough */
#endif
	case ODP_AUTH_ALG_AES_GCM:
		/* AES-GCM requires to do both auth and
		 * cipher at the same time */
		if (param->cipher_alg == ODP_CIPHER_ALG_AES_GCM || aes_gcm) {
			session->auth.func = null_crypto_routine;
			rc = 0;
		} else {
			rc = -1;
		}
		break;
	default:
		rc = -1;
	}

	/* Check result */
	if (rc) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_INV_AUTH;
		free_session(session);
		return -1;
	}

	/* We're happy */
	*session_out = (intptr_t)session;
	return 0;
}

int odp_crypto_session_destroy(odp_crypto_session_t session)
{
	odp_crypto_generic_session_t *generic;

#ifdef ODP_PKTIO_MVSAM
	return mvsam_odp_crypto_session_destroy(session);
#endif /* ODP_PKTIO_MVSAM */

	generic = (odp_crypto_generic_session_t *)(intptr_t)session;
	memset(generic, 0, sizeof(*generic));
	free_session(generic);
	return 0;
}

int
odp_crypto_operation(odp_crypto_op_param_t *param,
		     odp_bool_t *posted,
		     odp_crypto_op_result_t *result)
{
	odp_crypto_alg_err_t rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_alg_err_t rc_auth = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_generic_session_t *session;
	odp_crypto_op_result_t local_result;
	odp_bool_t allocated = false;
	
#ifdef ODP_PKTIO_MVSAM
	return mvsam_odp_crypto_operation(param, posted, result);
#endif /* ODP_PKTIO_MVSAM */
	session = (odp_crypto_generic_session_t *)(intptr_t)param->session;

	/* Resolve output buffer */
	if (ODP_PACKET_INVALID == param->out_pkt &&
	    ODP_POOL_INVALID != session->p.output_pool) {
		param->out_pkt = odp_packet_alloc(session->p.output_pool,
				odp_packet_len(param->pkt));
		allocated = true;
	}

	if (odp_unlikely(ODP_PACKET_INVALID == param->out_pkt)) {
		ODP_DBG("Alloc failed.\n");
		return -1;
	}

	if (param->pkt != param->out_pkt) {
		int ret;

		ret = odp_packet_copy_from_pkt(param->out_pkt,
					       0,
					       param->pkt,
					       0,
					       odp_packet_len(param->pkt));
		if (odp_unlikely(ret < 0))
			goto err;

		_odp_packet_copy_md_to_packet(param->pkt, param->out_pkt);
		odp_packet_free(param->pkt);
		param->pkt = ODP_PACKET_INVALID;
	}

	/* Invoke the functions */
	if (session->do_cipher_first) {
		rc_cipher = session->cipher.func(param, session);
		rc_auth = session->auth.func(param, session);
	} else {
		rc_auth = session->auth.func(param, session);
		rc_cipher = session->cipher.func(param, session);
	}

	/* Fill in result */
	local_result.ctx = param->ctx;
	local_result.pkt = param->out_pkt;
	local_result.cipher_status.alg_err = rc_cipher;
	local_result.cipher_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;
	local_result.auth_status.alg_err = rc_auth;
	local_result.auth_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;
	local_result.ok =
		(rc_cipher == ODP_CRYPTO_ALG_ERR_NONE) &&
		(rc_auth == ODP_CRYPTO_ALG_ERR_NONE);

	/* If specified during creation post event to completion queue */
	if (ODP_QUEUE_INVALID != session->p.compl_queue) {
		odp_event_t completion_event;
		odp_crypto_generic_op_result_t *op_result;

		/* Linux generic will always use packet for completion event */
		completion_event = odp_packet_to_event(param->out_pkt);
		_odp_buffer_event_type_set(
			odp_buffer_from_event(completion_event),
			ODP_EVENT_CRYPTO_COMPL);
		/* Asynchronous, build result (no HW so no errors) and send it*/
		op_result = get_op_result_from_event(completion_event);
		op_result->magic = OP_RESULT_MAGIC;
		op_result->result = local_result;
		if (odp_queue_enq(session->p.compl_queue, completion_event)) {
			odp_event_free(completion_event);
			goto err;
		}

		/* Indicate to caller operation was async */
		*posted = 1;
	} else {
		/* Synchronous, simply return results */
		if (!result)
			goto err;
		*result = local_result;

		/* Indicate to caller operation was sync */
		*posted = 0;
	}
	return 0;

err:
	if (allocated) {
		odp_packet_free(param->out_pkt);
		param->out_pkt = ODP_PACKET_INVALID;
	}

	return -1;
}

static void ODP_UNUSED openssl_thread_id(CRYPTO_THREADID ODP_UNUSED *id)
{
	CRYPTO_THREADID_set_numeric(id, odp_thread_id());
}

static void ODP_UNUSED openssl_lock(int mode, int n,
				    const char *file ODP_UNUSED,
				    int line ODP_UNUSED)
{
	if (mode & CRYPTO_LOCK)
		odp_ticketlock_lock((odp_ticketlock_t *)
				    &global->openssl_lock[n]);
	else
		odp_ticketlock_unlock((odp_ticketlock_t *)
				      &global->openssl_lock[n]);
}

int
odp_crypto_init_global(void)
{
	size_t mem_size;
	odp_shm_t shm;
	int idx;
	int nlocks = CRYPTO_num_locks();
#ifdef ODP_PKTIO_MVSAM
	int rc;
#endif /* ODP_PKTIO_MVSAM */

	/* Calculate the memory size we need */
	mem_size  = sizeof(*global);
	mem_size += (MAX_SESSIONS * sizeof(odp_crypto_generic_session_t));
	mem_size += nlocks * sizeof(odp_ticketlock_t);

	/* Allocate our globally shared memory */
	shm = odp_shm_reserve("crypto_pool", mem_size,
			      ODP_CACHE_LINE_SIZE, 0);

	global = odp_shm_addr(shm);

	/* Clear it out */
	memset(global, 0, mem_size);

	/* Initialize free list and lock */
	for (idx = 0; idx < MAX_SESSIONS; idx++) {
		global->sessions[idx].next = global->free;
		global->free = &global->sessions[idx];
	}
	odp_spinlock_init(&global->lock);

	if (nlocks > 0) {
		global->openssl_lock =
			(odp_ticketlock_t **)&global->sessions[MAX_SESSIONS];

		for (idx = 0; idx < nlocks; idx++)
			odp_ticketlock_init((odp_ticketlock_t *)
					    &global->openssl_lock[idx]);

		CRYPTO_THREADID_set_callback(openssl_thread_id);
		CRYPTO_set_locking_callback(openssl_lock);
	}

#ifdef ODP_PKTIO_MVSAM
	rc = mvsam_odp_crypto_init_global();
	if (rc != 0) {
		rc = odp_shm_free(odp_shm_lookup("crypto_pool"));
		if (rc < 0)
			ODP_ERR("shm free failed for crypto_pool\n");
		return rc;
	}
#endif /* ODP_PKTIO_MVSAM */

	return 0;
}

int odp_crypto_term_global(void)
{
	int rc = 0;
	int ret;
	int count = 0;
	odp_crypto_generic_session_t *session;

#ifdef ODP_PKTIO_MVSAM
	rc = mvsam_odp_crypto_term_global();
#endif /* ODP_PKTIO_MVSAM */

	for (session = global->free; session != NULL; session = session->next)
		count++;
	if (count != MAX_SESSIONS) {
		ODP_ERR("crypto sessions still active\n");
		rc = -1;
	}

	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_id_callback(NULL);

	ret = odp_shm_free(odp_shm_lookup("crypto_pool"));
	if (ret < 0) {
		ODP_ERR("shm free failed for crypto_pool\n");
		rc = -1;
	}

	return rc;
}

odp_random_kind_t odp_random_max_kind(void)
{
	return ODP_RANDOM_CRYPTO;
}

int32_t odp_random_data(uint8_t *buf, uint32_t len, odp_random_kind_t kind)
{
	int rc;

	switch (kind) {
	case ODP_RANDOM_BASIC:
		RAND_pseudo_bytes(buf, len);
		return len;

	case ODP_RANDOM_CRYPTO:
		rc = RAND_bytes(buf, len);
		return (1 == rc) ? (int)len /*success*/: -1 /*failure*/;

	case ODP_RANDOM_TRUE:
	default:
		return -1;
	}
}

int32_t odp_random_test_data(uint8_t *buf, uint32_t len, uint64_t *seed)
{
	union {
		uint32_t rand_word;
		uint8_t rand_byte[4];
	} u;
	uint32_t i = 0, j;
	uint32_t seed32 = (*seed) & 0xffffffff;

	while (i < len) {
		u.rand_word = rand_r(&seed32);

		for (j = 0; j < 4 && i < len; j++, i++)
			*buf++ = u.rand_byte[j];
	}

	*seed = seed32;
	return len;
}

odp_crypto_compl_t odp_crypto_compl_from_event(odp_event_t ev)
{
	/* This check not mandated by the API specification */
	if (odp_event_type(ev) != ODP_EVENT_CRYPTO_COMPL)
		ODP_ABORT("Event not a crypto completion");
	return (odp_crypto_compl_t)ev;
}

odp_event_t odp_crypto_compl_to_event(odp_crypto_compl_t completion_event)
{
	return (odp_event_t)completion_event;
}

void
odp_crypto_compl_result(odp_crypto_compl_t completion_event,
			odp_crypto_op_result_t *result)
{
#ifdef ODP_PKTIO_MVSAM
	struct crypto_thread_info *crp_thr;
#endif
	odp_event_t ev = odp_crypto_compl_to_event(completion_event);
	odp_crypto_generic_op_result_t *op_result;

	op_result = get_op_result_from_event(ev);

	if (OP_RESULT_MAGIC != op_result->magic)
		ODP_ABORT();

	memcpy(result, &op_result->result, sizeof(*result));
#ifdef ODP_PKTIO_MVSAM
	crp_thr       = get_crp_thread();
	if(odp_unlikely(crp_thr == NULL))
		return;

	crp_thr->app_enqs_cnt--;
#endif /* ODP_PKTIO_MVSAM */
}

void
odp_crypto_compl_free(odp_crypto_compl_t completion_event)
{
	_odp_buffer_event_type_set(
		odp_buffer_from_event((odp_event_t)completion_event),
		ODP_EVENT_PACKET);
}

void odp_crypto_session_param_init(odp_crypto_session_param_t *param)
{
	memset(param, 0, sizeof(odp_crypto_session_param_t));
}

uint64_t odp_crypto_session_to_u64(odp_crypto_session_t hdl)
{
	return (uint64_t)hdl;
}

uint64_t odp_crypto_compl_to_u64(odp_crypto_compl_t hdl)
{
	return _odp_pri(hdl);
}
