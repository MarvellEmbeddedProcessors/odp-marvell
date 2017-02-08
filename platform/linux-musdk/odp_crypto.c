/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

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

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#ifdef ODP_PKTIO_MVSAM
#include <drivers/mv_sam.h>
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


typedef struct odp_crypto_global_s odp_crypto_global_t;

struct odp_crypto_global_s {
	odp_spinlock_t                lock;
	odp_crypto_generic_session_t *free;
	odp_crypto_generic_session_t  sessions[0];

#ifdef ODP_PKTIO_MVSAM
	struct sam_cio               *cio;
#endif /* ODP_PKTIO_MVSAM */
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

	odp_queue_t    compl_queue;
	odp_pool_t     output_pool;
	char           iv[MAX_IV_SIZE];
	struct sam_sa *sa;
};

struct crypto_request {
	struct sam_buf_info sam_src_buf;
	struct sam_buf_info sam_dst_buf;
	odp_crypto_op_result_t	 result;
	struct crypto_session	*session;
};

static uint8_t	used_cios = MVSAM_CIOS_RSRV;

static unsigned int         num_session   = 0;
static struct crypto_session sessions[MVSAM_MAX_NUM_SESSIONS_PER_RING];

static unsigned int         app_enqs_cnt  = 0;
static unsigned int         io_enqs_cnt   = 0;
static unsigned int         io_enqs_offs  = 0;
static unsigned int         requests_cnt  = 0;
static unsigned int         requests_offs = 0;
static struct sam_cio_op_params	sam_op_params[MVSAM_RING_SIZE<<1];
static struct crypto_request	requests[MVSAM_RING_SIZE<<1];
#endif /* ODP_PKTIO_MVSAM */


static
odp_crypto_generic_op_result_t *get_op_result_from_event(odp_event_t ev)
{
	return &(odp_packet_hdr(odp_packet_from_event(ev))->op_result);
}

#ifdef ODP_PKTIO_MVSAM
static int find_free_cio(void)
{
	int	i;

	for (i = 0; i < MVSAM_TOTAL_NUM_CIOS; i++) {
		if (!((uint64_t)(1 << i) & used_cios)) {
			used_cios |= (uint64_t)(1 << i);
			break;
		}
	}
	if (i == MVSAM_TOTAL_NUM_CIOS) {
		ODP_ERR("no free CIO found!\n");
		return -ENOSPC;
	}
	return i;
}

static enum sam_auth_alg mvsam_get_auth_alg(odp_auth_alg_t auth_alg)
{
	switch(auth_alg)
	{
	case ODP_AUTH_ALG_NULL:
		return SAM_AUTH_NONE;
	case ODP_AUTH_ALG_MD5_96:
		return SAM_AUTH_HMAC_MD5;
	case ODP_AUTH_ALG_SHA256_128:
		return SAM_AUTH_HMAC_SHA2_256;
	case ODP_AUTH_ALG_AES128_GCM:
		return SAM_AUTH_AES_GCM;
	}
	return SAM_AUTH_NONE;
}

static int mvsam_odp_crypto_capability(odp_crypto_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_crypto_capability_t));
	capa->ciphers.bit.null = 1;
	capa->ciphers.bit.des = 1;
	capa->ciphers.bit.trides_cbc  = 1;
	capa->ciphers.bit.aes128_cbc  = 1;
	capa->ciphers.bit.aes128_gcm  = 1;
	capa->auths.bit.null = 1;
	capa->auths.bit.md5_96 = 1;
	capa->auths.bit.sha256_128 = 1;
	capa->auths.bit.aes128_gcm  = 1;
	capa->max_sessions = 20;
	return 0;
}

static int mvsam_odp_crypto_session_create(
	odp_crypto_session_params_t *params,
	odp_crypto_session_t *session_out,
	odp_crypto_ses_create_err_t *status)
{
	struct sam_session_params sam_session;
	struct sam_sa *sa = NULL;
	int    rc;

	/* check we aren't pass the maximum number of sessions*/
	if (odp_unlikely(num_session) == MVSAM_MAX_NUM_SESSIONS_PER_RING) {
		ODP_ERR("reach maximum sessions. failed to create a new session!\n");
		*status = -1;
		return -1;
	}

	memset(&sam_session, 0, sizeof(sam_session));
	sam_session.dir            = params->op;
	sam_session.cipher_alg     = params->cipher_alg;
	sam_session.cipher_mode    = SAM_CIPHER_CBC;
	sam_session.cipher_iv      = params->iv.data;
	sam_session.cipher_key     = params->cipher_key.data;
	sam_session.cipher_key_len = params->cipher_key.length;
	if(params->auth_alg != ODP_AUTH_ALG_NULL) {
		sam_session.auth_icv_len = 12;
		sam_session.auth_alg     = mvsam_get_auth_alg(params->auth_alg);
		sam_session.auth_inner   = NULL;
		sam_session.auth_outer   = NULL;
		sam_session.auth_aad_len = 0;
	}
	rc = sam_session_create(global->cio, &sam_session, &sa);
	if(odp_unlikely(rc)) {
		ODP_ERR("error while create new session\n");
		*status = -1;
		return -1;
	}
	ODP_DBG("crypto: session (%d) created\n", num_session);

	sessions[num_session].compl_queue = params->compl_queue;
	sessions[num_session].output_pool = params->output_pool;
	sessions[num_session].sa          = sa;
	memcpy(sessions[num_session].iv, sam_session.cipher_iv, MAX_IV_SIZE);

	*session_out = (odp_crypto_session_t)&sessions[num_session++];
	*status = 0;
	ODP_DBG("crypto: session-%d has created\n", num_session);
	return rc;
}

static int mvsam_odp_crypto_session_destroy(odp_crypto_session_t session)
{
	NOTUSED(session);
	ODP_UNIMPLEMENTED();
	return -1;
}

static inline int mvsam_result_enq(struct sam_cio_op_result *sam_res, int num_res)
{
	odp_event_t			 completion_events[MVSAM_RING_SIZE];
	odp_crypto_generic_op_result_t	*op_result;
	odp_queue_t			 compl_queue = NULL;
	int				 i;

	io_enqs_cnt -= num_res;

	for (i=0; i<num_res; i++) {
		struct crypto_request *result = (struct crypto_request *)sam_res[i].cookie;
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

	app_enqs_cnt += num_res;

	return 0;
}

static int mvsam_odp_crypto_operation(odp_crypto_op_params_t *params,
				      odp_bool_t *posted,
				      odp_crypto_op_result_t *result)
{
	struct crypto_session	*session;
	struct sam_cio_op_result sam_res_params[MVSAM_RING_SIZE];
	u16			 num_reqs;
	int			 rc = 0, flush_io_qs = 0;
	unsigned int		 tmp_offs;

	NOTUSED(result);

	if (app_enqs_cnt >= APP_Q_THRSHLD_HI) {
		ODP_DBG("App Q is full (%d)!\n", app_enqs_cnt);
		*posted = 0;
		result->ok = 0;
		return 0;
	}

	/* TODO: temporary W/A for immediate flushing of the SAM IO Qs
	 * until we support it correctly by timeouts */
	if (!params)
		flush_io_qs = 1;

	/* If we reach to the end of the ring, we need to "drain" it a little */
	if ((flush_io_qs && io_enqs_cnt) ||
	    (io_enqs_cnt >= IO_ENQ_THRSHLD_LO)) {
		num_reqs = PROCESS_PKT_BURST_SIZE;
		rc = sam_cio_deq(global->cio, sam_res_params, &num_reqs);
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

	if ((flush_io_qs && requests_cnt) ||
	    (requests_cnt >= REQ_THRSHLD_LO)) {
		num_reqs = PROCESS_PKT_BURST_SIZE;
		if ((io_enqs_offs > requests_offs) &&
		    ((REQ_THRSHLD_HI - io_enqs_offs) < PROCESS_PKT_BURST_SIZE))
			num_reqs = (REQ_THRSHLD_HI - io_enqs_offs);
		else if ((io_enqs_offs <= requests_offs) &&
		    ((requests_offs - io_enqs_offs) < PROCESS_PKT_BURST_SIZE))
			num_reqs = (requests_offs - io_enqs_offs);
		rc = sam_cio_enq(global->cio, &sam_op_params[io_enqs_offs], &num_reqs);
		if(odp_unlikely(rc)) {
			ODP_ERR("odp_musdk: failed to enqueue %d requests (%d)!\n",
				requests_cnt, rc);
			/* TODO: drop all err pkts! */
			return rc;
		}
		requests_cnt -= num_reqs;
		io_enqs_cnt += num_reqs;
		io_enqs_offs += num_reqs;
		if (io_enqs_offs == REQ_THRSHLD_HI)
			io_enqs_offs = 0;
	}

	if (flush_io_qs)
		return 0;

	tmp_offs = requests_offs+1;
	if (tmp_offs == REQ_THRSHLD_HI)
		tmp_offs = 0;
	if (tmp_offs == io_enqs_offs) {
		ODP_DBG("Requests ring is full (%d)!\n", requests_cnt);
		*posted = 0;
		result->ok = 0;
		return 0;
	}

	session  = (struct crypto_session *)params->session;

	sam_op_params[requests_offs].cipher_len    = params->cipher_range.length;
	sam_op_params[requests_offs].cipher_offset =
		odp_packet_headroom(params->pkt) + params->cipher_range.offset;
	sam_op_params[requests_offs].cookie        = &requests[requests_offs];
	sam_op_params[requests_offs].sa            = session->sa;

	requests[requests_offs].sam_src_buf.len   =
		odp_packet_headroom(params->pkt) + odp_packet_len(params->pkt);
	requests[requests_offs].sam_src_buf.vaddr = odp_packet_data(params->pkt);
	requests[requests_offs].sam_src_buf.paddr =
		mv_sys_dma_mem_virt2phys((void *)((uintptr_t)odp_packet_head(params->pkt)));

	/* TODO: need to get the real buffer size from the odp_buffer structure. */
	requests[requests_offs].sam_dst_buf.len   =
		odp_packet_headroom(params->pkt) + odp_packet_len(params->pkt) + 64;
	requests[requests_offs].sam_dst_buf.vaddr = odp_packet_data(params->out_pkt);
	requests[requests_offs].sam_dst_buf.paddr =
		mv_sys_dma_mem_virt2phys((void *)((uintptr_t)odp_packet_head(params->out_pkt)));

	sam_op_params[requests_offs].src = &requests[requests_offs].sam_src_buf;
	sam_op_params[requests_offs].dst = &requests[requests_offs].sam_dst_buf;

	sam_op_params[requests_offs].auth_len    = params->auth_range.length;
	sam_op_params[requests_offs].auth_offset = params->auth_range.offset;
	sam_op_params[requests_offs].num_bufs    = 1;

	if (params->override_iv_ptr != 0)
		sam_op_params[requests_offs].cipher_iv = params->override_iv_ptr;
	else
		sam_op_params[requests_offs].cipher_iv = (u8 *)session->iv;

	requests[requests_offs].result.ctx = params->ctx;
	requests[requests_offs].result.pkt = params->out_pkt;
	requests[requests_offs].session = session;
	requests_offs++;
	if (requests_offs == REQ_THRSHLD_HI)
		requests_offs = 0;
	requests_cnt++;

	/* Indicate to caller operation was async, */
	/* no packet received from device          */
	*posted = 1;

	return 0;
}

static int mvsam_odp_crypto_init_global(void)
{
	struct sam_cio_params		cio_params;
	char				name[15];
	int				err, cio_id;

	cio_id = find_free_cio();
	if (cio_id < 0) {
		ODP_ERR("free CIO not found!\n");
		return cio_id;
	}
	memset(name, 0, sizeof(name));
	snprintf(name, sizeof(name), "cio-%d:%d", 0, cio_id);
	ODP_PRINT("found cio: %s\n", name);
	memset(&cio_params, 0, sizeof(cio_params));
	cio_params.match = name;
	cio_params.size = MVSAM_RING_SIZE;
	cio_params.num_sessions = MVSAM_MAX_NUM_SESSIONS_PER_RING;
	/* TODO: what is the size of the buffer */
	cio_params.max_buf_size = 2048;
	err = sam_cio_init(&cio_params, &global->cio);
	if (err != 0)
		return err;
	if (!global->cio) {
		ODP_ERR("CIO init failed!\n");
		return -1;
	}
	ODP_DBG("crypto: allocate crp_op_request - %d\n", cio_params.size);
	memset(sam_op_params, 0, sizeof(sam_op_params));

	return 0;
}

static int mvsam_odp_crypto_term_global(void)
{
	sam_cio_deinit(global->cio);
	return 0;
}
#endif /* ODP_PKTIO_MVSAM */

static
odp_crypto_generic_session_t *alloc_session(void)
{
	odp_crypto_generic_session_t *session = NULL;

	odp_spinlock_lock(&global->lock);
	session = global->free;
	if (session)
		global->free = session->next;
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
null_crypto_routine(odp_crypto_op_params_t *params ODP_UNUSED,
		    odp_crypto_generic_session_t *session ODP_UNUSED)
{
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t md5_gen(odp_crypto_op_params_t *params,
			     odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint8_t *icv   = data;
	uint32_t len   = params->auth_range.length;
	uint8_t  hash[EVP_MAX_MD_SIZE];

	/* Adjust pointer for beginning of area to auth */
	data += params->auth_range.offset;
	icv  += params->hash_result_offset;

	/* Hash it */
	HMAC(EVP_md5(),
	     session->auth.data.md5.key,
	     16,
	     data,
	     len,
	     hash,
	     NULL);

	/* Copy to the output location */
	memcpy(icv, hash, session->auth.data.md5.bytes);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t md5_check(odp_crypto_op_params_t *params,
			       odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint8_t *icv   = data;
	uint32_t len   = params->auth_range.length;
	uint32_t bytes = session->auth.data.md5.bytes;
	uint8_t  hash_in[EVP_MAX_MD_SIZE];
	uint8_t  hash_out[EVP_MAX_MD_SIZE];

	/* Adjust pointer for beginning of area to auth */
	data += params->auth_range.offset;
	icv  += params->hash_result_offset;

	/* Copy current value out and clear it before authentication */
	memset(hash_in, 0, sizeof(hash_in));
	memcpy(hash_in, icv, bytes);
	memset(icv, 0, bytes);
	memset(hash_out, 0, sizeof(hash_out));

	/* Hash it */
	HMAC(EVP_md5(),
	     session->auth.data.md5.key,
	     16,
	     data,
	     len,
	     hash_out,
	     NULL);

	/* Verify match */
	if (0 != memcmp(hash_in, hash_out, bytes))
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	/* Matched */
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t sha256_gen(odp_crypto_op_params_t *params,
				odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint8_t *icv   = data;
	uint32_t len   = params->auth_range.length;
	uint8_t  hash[EVP_MAX_MD_SIZE];

	/* Adjust pointer for beginning of area to auth */
	data += params->auth_range.offset;
	icv  += params->hash_result_offset;

	/* Hash it */
	HMAC(EVP_sha256(),
	     session->auth.data.sha256.key,
	     32,
	     data,
	     len,
	     hash,
	     NULL);

	/* Copy to the output location */
	memcpy(icv, hash, session->auth.data.sha256.bytes);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t sha256_check(odp_crypto_op_params_t *params,
				  odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint8_t *icv   = data;
	uint32_t len   = params->auth_range.length;
	uint32_t bytes = session->auth.data.sha256.bytes;
	uint8_t  hash_in[EVP_MAX_MD_SIZE];
	uint8_t  hash_out[EVP_MAX_MD_SIZE];

	/* Adjust pointer for beginning of area to auth */
	data += params->auth_range.offset;
	icv  += params->hash_result_offset;

	/* Copy current value out and clear it before authentication */
	memset(hash_in, 0, sizeof(hash_in));
	memcpy(hash_in, icv, bytes);
	memset(icv, 0, bytes);
	memset(hash_out, 0, sizeof(hash_out));

	/* Hash it */
	HMAC(EVP_sha256(),
	     session->auth.data.sha256.key,
	     32,
	     data,
	     len,
	     hash_out,
	     NULL);

	/* Verify match */
	if (0 != memcmp(hash_in, hash_out, bytes))
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	/* Matched */
	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t aes_encrypt(odp_crypto_op_params_t *params,
				 odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t len   = params->cipher_range.length;
	unsigned char iv_enc[AES_BLOCK_SIZE];
	void *iv_ptr;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv_enc, iv_ptr, AES_BLOCK_SIZE);

	/* Adjust pointer for beginning of area to cipher */
	data += params->cipher_range.offset;
	/* Encrypt it */
	AES_cbc_encrypt(data, data, len, &session->cipher.data.aes.key,
			iv_enc, AES_ENCRYPT);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t aes_decrypt(odp_crypto_op_params_t *params,
				 odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t len   = params->cipher_range.length;
	unsigned char iv_enc[AES_BLOCK_SIZE];
	void *iv_ptr;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv_enc, iv_ptr, AES_BLOCK_SIZE);

	/* Adjust pointer for beginning of area to cipher */
	data += params->cipher_range.offset;
	/* Encrypt it */
	AES_cbc_encrypt(data, data, len, &session->cipher.data.aes.key,
			iv_enc, AES_DECRYPT);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
int process_aes_params(odp_crypto_generic_session_t *session,
		       odp_crypto_session_params_t *params)
{
	/* Verify IV len is either 0 or 16 */
	if (!((0 == params->iv.length) || (16 == params->iv.length)))
		return -1;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == params->op) {
		session->cipher.func = aes_encrypt;
		AES_set_encrypt_key(params->cipher_key.data, 128,
				    &session->cipher.data.aes.key);
	} else {
		session->cipher.func = aes_decrypt;
		AES_set_decrypt_key(params->cipher_key.data, 128,
				    &session->cipher.data.aes.key);
	}

	return 0;
}

static
odp_crypto_alg_err_t aes_gcm_encrypt(odp_crypto_op_params_t *params,
				     odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t plain_len   = params->cipher_range.length;
	uint8_t *aad_head = data + params->auth_range.offset;
	uint8_t *aad_tail = data + params->cipher_range.offset +
		params->cipher_range.length;
	uint32_t auth_len = params->auth_range.length;
	unsigned char iv_enc[AES_BLOCK_SIZE];
	void *iv_ptr;
	uint8_t *tag = data + params->hash_result_offset;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/* All cipher data must be part of the authentication */
	if (params->auth_range.offset > params->cipher_range.offset ||
	    params->auth_range.offset + auth_len <
	    params->cipher_range.offset + plain_len)
		return ODP_CRYPTO_ALG_ERR_DATA_SIZE;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv_enc, iv_ptr, AES_BLOCK_SIZE);

	/* Adjust pointer for beginning of area to cipher/auth */
	uint8_t *plaindata = data + params->cipher_range.offset;

	/* Encrypt it */
	EVP_CIPHER_CTX *ctx = session->cipher.data.aes_gcm.ctx;
	int cipher_len = 0;

	EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv_enc);

	/* Authenticate header data (if any) without encrypting them */
	if (aad_head < plaindata) {
		EVP_EncryptUpdate(ctx, NULL, &cipher_len,
				  aad_head, plaindata - aad_head);
	}

	EVP_EncryptUpdate(ctx, plaindata, &cipher_len,
			  plaindata, plain_len);
	cipher_len = plain_len;

	/* Authenticate footer data (if any) without encrypting them */
	if (aad_head + auth_len > plaindata + plain_len) {
		EVP_EncryptUpdate(ctx, NULL, NULL, aad_tail,
				  auth_len - (aad_tail - aad_head));
	}

	EVP_EncryptFinal_ex(ctx, plaindata + cipher_len, &cipher_len);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t aes_gcm_decrypt(odp_crypto_op_params_t *params,
				     odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t cipher_len   = params->cipher_range.length;
	uint8_t *aad_head = data + params->auth_range.offset;
	uint8_t *aad_tail = data + params->cipher_range.offset +
		params->cipher_range.length;
	uint32_t auth_len = params->auth_range.length;
	unsigned char iv_enc[AES_BLOCK_SIZE];
	void *iv_ptr;
	uint8_t *tag   = data + params->hash_result_offset;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/* All cipher data must be part of the authentication */
	if (params->auth_range.offset > params->cipher_range.offset ||
	    params->auth_range.offset + auth_len <
	    params->cipher_range.offset + cipher_len)
		return ODP_CRYPTO_ALG_ERR_DATA_SIZE;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv_enc, iv_ptr, AES_BLOCK_SIZE);

	/* Adjust pointer for beginning of area to cipher/auth */
	uint8_t *cipherdata = data + params->cipher_range.offset;
	/* Encrypt it */
	EVP_CIPHER_CTX *ctx = session->cipher.data.aes_gcm.ctx;
	int plain_len = 0;

	EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv_enc);

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

	/* Authenticate header data (if any) without encrypting them */
	if (aad_head < cipherdata) {
		EVP_DecryptUpdate(ctx, NULL, &plain_len,
				  aad_head, cipherdata - aad_head);
	}

	EVP_DecryptUpdate(ctx, cipherdata, &plain_len,
			  cipherdata, cipher_len);
	plain_len = cipher_len;

	/* Authenticate footer data (if any) without encrypting them */
	if (aad_head + auth_len > cipherdata + cipher_len) {
		EVP_DecryptUpdate(ctx, NULL, NULL, aad_tail,
				  auth_len - (aad_tail - aad_head));
	}

	if (EVP_DecryptFinal_ex(ctx, cipherdata + cipher_len, &plain_len) < 0)
		return ODP_CRYPTO_ALG_ERR_ICV_CHECK;

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
int process_aes_gcm_params(odp_crypto_generic_session_t *session,
			   odp_crypto_session_params_t *params)
{
	/* Verify Key len is 16 */
	if (params->cipher_key.length != 16)
		return -1;

	/* Set function */
	EVP_CIPHER_CTX *ctx =
		session->cipher.data.aes_gcm.ctx = EVP_CIPHER_CTX_new();

	if (ODP_CRYPTO_OP_ENCODE == params->op) {
		session->cipher.func = aes_gcm_encrypt;
		EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	} else {
		session->cipher.func = aes_gcm_decrypt;
		EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
	}

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
			    params->iv.length, NULL);
	if (ODP_CRYPTO_OP_ENCODE == params->op) {
		EVP_EncryptInit_ex(ctx, NULL, NULL,
				   params->cipher_key.data, NULL);
	} else {
		EVP_DecryptInit_ex(ctx, NULL, NULL,
				   params->cipher_key.data, NULL);
	}

	return 0;
}

static
odp_crypto_alg_err_t des_encrypt(odp_crypto_op_params_t *params,
				 odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t len   = params->cipher_range.length;
	DES_cblock iv;
	void *iv_ptr;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv, iv_ptr, sizeof(iv));

	/* Adjust pointer for beginning of area to cipher */
	data += params->cipher_range.offset;
	/* Encrypt it */
	DES_ede3_cbc_encrypt(data,
			     data,
			     len,
			     &session->cipher.data.des.ks1,
			     &session->cipher.data.des.ks2,
			     &session->cipher.data.des.ks3,
			     &iv,
			     1);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
odp_crypto_alg_err_t des_decrypt(odp_crypto_op_params_t *params,
				 odp_crypto_generic_session_t *session)
{
	uint8_t *data  = odp_packet_data(params->out_pkt);
	uint32_t len   = params->cipher_range.length;
	DES_cblock iv;
	void *iv_ptr;

	if (params->override_iv_ptr)
		iv_ptr = params->override_iv_ptr;
	else if (session->cipher.iv.data)
		iv_ptr = session->cipher.iv.data;
	else
		return ODP_CRYPTO_ALG_ERR_IV_INVALID;

	/*
	 * Create a copy of the IV.  The DES library modifies IV
	 * and if we are processing packets on parallel threads
	 * we could get corruption.
	 */
	memcpy(iv, iv_ptr, sizeof(iv));

	/* Adjust pointer for beginning of area to cipher */
	data += params->cipher_range.offset;

	/* Decrypt it */
	DES_ede3_cbc_encrypt(data,
			     data,
			     len,
			     &session->cipher.data.des.ks1,
			     &session->cipher.data.des.ks2,
			     &session->cipher.data.des.ks3,
			     &iv,
			     0);

	return ODP_CRYPTO_ALG_ERR_NONE;
}

static
int process_des_params(odp_crypto_generic_session_t *session,
		       odp_crypto_session_params_t *params)
{
	/* Verify IV len is either 0 or 8 */
	if (!((0 == params->iv.length) || (8 == params->iv.length)))
		return -1;

	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == params->op)
		session->cipher.func = des_encrypt;
	else
		session->cipher.func = des_decrypt;

	/* Convert keys */
	DES_set_key((DES_cblock *)&params->cipher_key.data[0],
		    &session->cipher.data.des.ks1);
	DES_set_key((DES_cblock *)&params->cipher_key.data[8],
		    &session->cipher.data.des.ks2);
	DES_set_key((DES_cblock *)&params->cipher_key.data[16],
		    &session->cipher.data.des.ks3);

	return 0;
}

static
int process_md5_params(odp_crypto_generic_session_t *session,
		       odp_crypto_session_params_t *params,
		       uint32_t bits)
{
	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == params->op)
		session->auth.func = md5_gen;
	else
		session->auth.func = md5_check;

	/* Number of valid bytes */
	session->auth.data.md5.bytes = bits / 8;

	/* Convert keys */
	memcpy(session->auth.data.md5.key, params->auth_key.data, 16);

	return 0;
}

static
int process_sha256_params(odp_crypto_generic_session_t *session,
			  odp_crypto_session_params_t *params,
			  uint32_t bits)
{
	/* Set function */
	if (ODP_CRYPTO_OP_ENCODE == params->op)
		session->auth.func = sha256_gen;
	else
		session->auth.func = sha256_check;

	/* Number of valid bytes */
	session->auth.data.sha256.bytes = bits / 8;

	/* Convert keys */
	memcpy(session->auth.data.sha256.key, params->auth_key.data, 32);

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

	capa->ciphers.bit.null = 1;
	capa->ciphers.bit.des = 1;
	capa->ciphers.bit.trides_cbc  = 1;
	capa->ciphers.bit.aes128_cbc  = 1;
	capa->ciphers.bit.aes128_gcm  = 1;

	capa->auths.bit.null = 1;
	capa->auths.bit.md5_96 = 1;
	capa->auths.bit.sha256_128 = 1;
	capa->auths.bit.aes128_gcm  = 1;

	capa->max_sessions = MAX_SESSIONS;

	return 0;
}

int
odp_crypto_session_create(odp_crypto_session_params_t *params,
			  odp_crypto_session_t *session_out,
			  odp_crypto_ses_create_err_t *status)
{
	int rc;
	odp_crypto_generic_session_t *session;
#ifdef ODP_PKTIO_MVSAM
	return mvsam_odp_crypto_session_create(params, session_out, status);
#endif /* ODP_PKTIO_MVSAM */

	/* Default to successful result */
	*status = ODP_CRYPTO_SES_CREATE_ERR_NONE;

	/* Allocate memory for this session */
	session = alloc_session();
	if (NULL == session) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_ENOMEM;
		return -1;
	}

	/* Derive order */
	if (ODP_CRYPTO_OP_ENCODE == params->op)
		session->do_cipher_first =  params->auth_cipher_text;
	else
		session->do_cipher_first = !params->auth_cipher_text;

	/* Copy stuff over */
	session->op = params->op;
	session->compl_queue = params->compl_queue;
	session->cipher.alg  = params->cipher_alg;
	session->cipher.iv.data = params->iv.data;
	session->cipher.iv.len  = params->iv.length;
	session->auth.alg  = params->auth_alg;
	session->output_pool = params->output_pool;

	/* Process based on cipher */
	switch (params->cipher_alg) {
	case ODP_CIPHER_ALG_NULL:
		session->cipher.func = null_crypto_routine;
		rc = 0;
		break;
	case ODP_CIPHER_ALG_DES:
	case ODP_CIPHER_ALG_3DES_CBC:
		rc = process_des_params(session, params);
		break;
	case ODP_CIPHER_ALG_AES128_CBC:
		rc = process_aes_params(session, params);
		break;
	case ODP_CIPHER_ALG_AES128_GCM:
		/* AES-GCM requires to do both auth and
		 * cipher at the same time
		 */
		if (params->auth_alg != ODP_AUTH_ALG_AES128_GCM) {
			rc = -1;
			break;
		}
		rc = process_aes_gcm_params(session, params);
		break;
	default:
		rc = -1;
	}

	/* Check result */
	if (rc) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER;
		return -1;
	}

	/* Process based on auth */
	switch (params->auth_alg) {
	case ODP_AUTH_ALG_NULL:
		session->auth.func = null_crypto_routine;
		rc = 0;
		break;
	case ODP_AUTH_ALG_MD5_96:
		rc = process_md5_params(session, params, 96);
		break;
	case ODP_AUTH_ALG_SHA256_128:
		rc = process_sha256_params(session, params, 128);
		break;
	case ODP_AUTH_ALG_AES128_GCM:
		/* AES-GCM requires to do both auth and
		 * cipher at the same time
		 */
		if (params->cipher_alg != ODP_CIPHER_ALG_AES128_GCM) {
			rc = -1;
			break;
		}
		session->auth.func = null_crypto_routine;
		rc = 0;
		break;
	default:
		rc = -1;
	}

	/* Check result */
	if (rc) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_INV_AUTH;
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
	if (generic->cipher.alg == ODP_CIPHER_ALG_AES128_GCM)
		EVP_CIPHER_CTX_free(generic->cipher.data.aes_gcm.ctx);
	memset(generic, 0, sizeof(*generic));
	free_session(generic);
	return 0;
}

int
odp_crypto_operation(odp_crypto_op_params_t *params,
		     odp_bool_t *posted,
		     odp_crypto_op_result_t *result)
{
	odp_crypto_alg_err_t rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_alg_err_t rc_auth = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_generic_session_t *session;
	odp_crypto_op_result_t local_result;

#ifdef ODP_PKTIO_MVSAM
	return mvsam_odp_crypto_operation(params, posted, result);
#endif /* ODP_PKTIO_MVSAM */
	session = (odp_crypto_generic_session_t *)(intptr_t)params->session;

	/* Resolve output buffer */
	if (ODP_PACKET_INVALID == params->out_pkt &&
	    ODP_POOL_INVALID != session->output_pool)
		params->out_pkt = odp_packet_alloc(session->output_pool,
				odp_packet_len(params->pkt));
	if (params->pkt != params->out_pkt) {
		if (odp_unlikely(ODP_PACKET_INVALID == params->out_pkt))
			ODP_ABORT();
		(void)odp_packet_copy_from_pkt(params->out_pkt,
					       0,
					       params->pkt,
					       0,
					       odp_packet_len(params->pkt));
		_odp_packet_copy_md_to_packet(params->pkt, params->out_pkt);
		odp_packet_free(params->pkt);
		params->pkt = ODP_PACKET_INVALID;
	}

	/* Invoke the functions */
	if (session->do_cipher_first) {
		rc_cipher = session->cipher.func(params, session);
		rc_auth = session->auth.func(params, session);
	} else {
		rc_auth = session->auth.func(params, session);
		rc_cipher = session->cipher.func(params, session);
	}

	/* Fill in result */
	local_result.ctx = params->ctx;
	local_result.pkt = params->out_pkt;
	local_result.cipher_status.alg_err = rc_cipher;
	local_result.cipher_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;
	local_result.auth_status.alg_err = rc_auth;
	local_result.auth_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;
	local_result.ok =
		(rc_cipher == ODP_CRYPTO_ALG_ERR_NONE) &&
		(rc_auth == ODP_CRYPTO_ALG_ERR_NONE);

	/* If specified during creation post event to completion queue */
	if (ODP_QUEUE_INVALID != session->compl_queue) {
		odp_event_t completion_event;
		odp_crypto_generic_op_result_t *op_result;

		/* Linux generic will always use packet for completion event */
		completion_event = odp_packet_to_event(params->out_pkt);
		_odp_buffer_event_type_set(
			odp_buffer_from_event(completion_event),
			ODP_EVENT_CRYPTO_COMPL);
		/* Asynchronous, build result (no HW so no errors) and send it*/
		op_result = get_op_result_from_event(completion_event);
		op_result->magic = OP_RESULT_MAGIC;
		op_result->result = local_result;
		if (odp_queue_enq(session->compl_queue, completion_event)) {
			odp_event_free(completion_event);
			return -1;
		}

		/* Indicate to caller operation was async */
		*posted = 1;
	} else {
		/* Synchronous, simply return results */
		if (!result)
			return -1;
		*result = local_result;

		/* Indicate to caller operation was sync */
		*posted = 0;
	}
	return 0;
}

int
odp_crypto_init_global(void)
{
	size_t mem_size;
	odp_shm_t shm;
	int idx;
#ifdef ODP_PKTIO_MVSAM
	int rc;
#endif /* ODP_PKTIO_MVSAM */

	/* Calculate the memory size we need */
	mem_size  = sizeof(*global);
	mem_size += (MAX_SESSIONS * sizeof(odp_crypto_generic_session_t));

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

	ret = odp_shm_free(odp_shm_lookup("crypto_pool"));
	if (ret < 0) {
		ODP_ERR("shm free failed for crypto_pool\n");
		rc = -1;
	}

	return rc;
}

int32_t
odp_random_data(uint8_t *buf, int32_t len, odp_bool_t use_entropy ODP_UNUSED)
{
	int32_t rc;
	rc = RAND_bytes(buf, len);
	return (1 == rc) ? len /*success*/: -1 /*failure*/;
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
	odp_event_t ev = odp_crypto_compl_to_event(completion_event);
	odp_crypto_generic_op_result_t *op_result;

	op_result = get_op_result_from_event(ev);

	if (OP_RESULT_MAGIC != op_result->magic)
		ODP_ABORT();

	memcpy(result, &op_result->result, sizeof(*result));
#ifdef ODP_PKTIO_MVSAM
	app_enqs_cnt--;
#endif /* ODP_PKTIO_MVSAM */
}

void
odp_crypto_compl_free(odp_crypto_compl_t completion_event)
{
	_odp_buffer_event_type_set(
		odp_buffer_from_event((odp_event_t)completion_event),
		ODP_EVENT_PACKET);
}
