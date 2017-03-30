/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_example_ipsec.c  ODP basic packet IO cross connect with IPsec test application
 */

/* enable strtok */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>

#include <example_debug.h>

#include <odp_api.h>

#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/icmp.h>
#include <odp/helper/ipsec.h>

#include <stdbool.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <odp_ipsec_misc.h>
#include <odp_ipsec_sa_db.h>
#include <odp_ipsec_sp_db.h>
#include <odp_ipsec_fwd_db.h>
#include <odp_ipsec_loop_db.h>
#include <odp_ipsec_cache.h>
#include <odp_ipsec_stream.h>

#define UNUSED			__attribute__((__unused__))

//#define IPSEC_DEBUG
#define MEMMOVE_OPTIMIZED


#ifdef IPSEC_DEBUG
#define dprintf printf
#define LOG_ABORT(fmt, ...) printf("LOG_ABORT %s %d\n", __func__, __LINE__);
#else
#define dprintf(fmt...)
#endif

/**
 * Buffer pool for packet IO
 */
#define SHM_PKT_POOL_BUF_COUNT 1024
#define SHM_PKT_POOL_BUF_SIZE  2048
#define SHM_PKT_POOL_SIZE      (SHM_PKT_POOL_BUF_COUNT * SHM_PKT_POOL_BUF_SIZE)

/**
 * Buffer pool for crypto session output packets
 */
#define SHM_OUT_POOL_BUF_COUNT 1024
#define SHM_OUT_POOL_BUF_SIZE  2048
#define SHM_OUT_POOL_SIZE      (SHM_OUT_POOL_BUF_COUNT * SHM_OUT_POOL_BUF_SIZE)

#define SHM_CTX_POOL_BUF_SIZE  (sizeof(pkt_ctx_t))
#define SHM_CTX_POOL_BUF_COUNT (SHM_PKT_POOL_BUF_COUNT + SHM_OUT_POOL_BUF_COUNT)
#define SHM_CTX_POOL_SIZE      (SHM_CTX_POOL_BUF_COUNT * SHM_CTX_POOL_BUF_SIZE)

#define MAX_WORKERS     4   /**< maximum number of worker threads */

#define POOL_SEG_LEN	1856
#define MAX_PKT_BURST	32
#define MAX_CTX_DB      MAX_PKT_BURST*8    /* 256 */

#define MAX_NB_PKTIO	2
#define MAX_NB_QUEUE	2

#define MAX_CRYPTO_TO_CPU_PKT_THREASHOULD 256

#define CHECK_RC(rc,ctx,pkt_tbl,i,j)  if(rc==PKT_DROP){free_pkt_ctx(ctx[i]);odp_packet_free(pkt_tbl[i]);continue;}
//#define CHECK_RC(rc,ctx,pkt_tbl,i,j)  if((rc!=PKT_CONTINUE)&&(rc!=PKT_POSTED)){printf("NOT CONTINUE!!! rc=%d i=%d j=%d\n",rc,i,j);}

//#define PKT_ECHO_SUPPORT
#define USE_APP_PREFETCH
#define PREFETCH_SHIFT         3

#define EMPTY_RX_THRESHOULD 100

#define ODP_AUTH_ALG_MD5_96_ICV_LEN 12

//#define CHECK_CYCLES
#ifdef CHECK_CYCLES
#include <sys/time.h>   // for gettimeofday()
#define CLK_MHZ	2000
static signed int long long usecs1=0, cnt1=0;
static struct timeval t1, t2;

#define START_COUNT_CYCLES	\
	gettimeofday(&t1, NULL);
#define STOP_N_REPORT_COUNT_CYCLES(_num,_max)	\
do {						\
	gettimeofday(&t2, NULL);		\
	/* compute and print the elapsed time in millisec */	\
	if (_num) {				\
		usecs1 += (t2.tv_sec - t1.tv_sec) * 1000000.0;	\
		usecs1 += (t2.tv_usec - t1.tv_usec);		\
		cnt1+=_num;		\
	}				\
	if (cnt1 >= _max) {		\
		printf("Cycles count: %lld\n",	\
			usecs1*CLK_MHZ/cnt1);	\
		usecs1=cnt1=0;		\
	}				\
} while (0);

#else
#define START_COUNT_CYCLES
#define STOP_N_REPORT_COUNT_CYCLES(_num,_max)
#endif /* CHECK_CYCLES */


/**
 * Parsed command line application arguments
 */
typedef struct {
	int cpu_count;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	crypto_api_mode_e mode;	/**< Crypto API preferred mode */
	odp_pool_t pool;	/**< Buffer pool for packet IO */
	char *if_str;		/**< Storage for interface names */
} appl_args_t;

/**
 * Grouping of both parsed CL args and thread specific args - alloc together
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
} args_t;

/**
 * Packet processing states/steps
 */
typedef enum {
	PKT_STATE_INPUT_VERIFY,        /**< Verify IPv4 and ETH */
	PKT_STATE_IPSEC_IN_CLASSIFY,   /**< Initiate input IPsec */
	PKT_STATE_IPSEC_IN_FINISH,     /**< Finish input IPsec */
	PKT_STATE_ROUTE_LOOKUP,        /**< Use DST IP to find output IF */
	PKT_STATE_IPSEC_OUT_CLASSIFY,  /**< Intiate output IPsec */
	PKT_STATE_IPSEC_OUT_SEQ,       /**< Assign IPsec sequence numbers */
	PKT_STATE_IPSEC_OUT_FINISH,    /**< Finish output IPsec */
	PKT_STATE_TRANSMIT,            /**< Send packet to output IF queue */
} pkt_state_e;

/**
 * Packet processing result codes
 */
typedef enum {
	PKT_CONTINUE,    /**< No events posted, keep processing */
	PKT_POSTED,      /**< Event posted, stop processing */
	PKT_DROP,        /**< Reason to drop detected, stop processing */
	PKT_DONE         /**< Finished with packet, stop processing */
} pkt_disposition_e;

/**
 * Per packet IPsec processing context
 */
typedef struct {
	uint8_t  ip_tos;         /**< Saved IP TOS value */
	uint16_t ip_frag_offset; /**< Saved IP flags value */
	uint8_t  ip_ttl;         /**< Saved IP TTL value */
	int      hdr_len;        /**< Length of IPsec headers */
	int      trl_len;        /**< Length of IPsec trailers */
	uint16_t tun_hdr_offset; /**< Offset of tunnel header from
				      buffer start */
	uint16_t ah_offset;      /**< Offset of AH header from buffer start */
	uint16_t esp_offset;     /**< Offset of ESP header from buffer start */
    odp_auth_alg_t auth_alg; /**< Authentication algorithm */

	/* Input only */
	uint32_t src_ip;         /**< SA source IP address */
	uint32_t dst_ip;         /**< SA dest IP address */

	/* Output only */
	odp_crypto_op_params_t params;  /**< Parameters for crypto call */
	uint32_t *ah_seq;               /**< AH sequence number location */
	uint32_t *esp_seq;              /**< ESP sequence number location */
	uint16_t *tun_hdr_id;           /**< Tunnel header ID > */
} ipsec_ctx_t;

/**
 * Per packet processing context
 */
typedef struct {
	odp_buffer_t buffer;  /**< Buffer for context */
	pkt_state_e  state;   /**< Next processing step */
	ipsec_ctx_t  ipsec;   /**< IPsec specific context */
	odp_pktout_queue_t pktout; /**< Packet output queue */
} pkt_ctx_t;

struct l3fwd_pktio_s {
	odp_pktio_t pktio;
//	odph_ethaddr_t mac_addr;
	odp_pktin_queue_t ifin[MAX_NB_QUEUE];
	odp_pktout_queue_t ifout[MAX_NB_QUEUE];
};


/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);


static odp_pool_t pkt_pool = ODP_POOL_INVALID;

/** Global pointer to args */
static args_t *args;

static odp_pool_t out_pool = ODP_POOL_INVALID;

/** ATOMIC queue for IPsec sequence number assignment */
static odp_queue_t seqnumq;

/** ORDERED queue (eventually) for per packet crypto API completion events */
static odp_queue_t completionq;

/** Synchronize threads before packet processing begins */
static odp_barrier_t sync_barrier;

static odp_pool_t ctx_pool = ODP_POOL_INVALID;

static struct l3fwd_pktio_s port_io_config[MAX_NB_PKTIO];


#ifdef PKT_ECHO_SUPPORT
static inline void swap_l2(char *buf)
{
	uint16_t *eth_hdr;
	register uint16_t tmp;

	eth_hdr = (uint16_t *)buf;
	tmp = eth_hdr[0];
	eth_hdr[0] = eth_hdr[3];
	eth_hdr[3] = tmp;
	tmp = eth_hdr[1];
	eth_hdr[1] = eth_hdr[4];
	eth_hdr[4] = tmp;
	tmp = eth_hdr[2];
	eth_hdr[2] = eth_hdr[5];
	eth_hdr[5] = tmp;
}

static inline void swap_l3(char *buf)
{
	register uint32_t tmp32;

	buf += 14 + 12;
	tmp32 = ((uint32_t *)buf)[0];
	((uint32_t *)buf)[0] = ((uint32_t *)buf)[1];
	((uint32_t *)buf)[1] = tmp32;
}
#endif /* PKT_ECHO_SUPPORT */

/**
  Context Buffer Manager
*/

static int ctx_buf_mng_next_free_index;
static odp_buffer_t ctx_buf_mng_db[MAX_CTX_DB];

static void ctx_buf_mng_init(void) {

	for (int i = 0; i < MAX_CTX_DB; i++) {
		ctx_buf_mng_db[i] = odp_buffer_alloc(ctx_pool);

		if (odp_unlikely(ODP_BUFFER_INVALID == ctx_buf_mng_db[i])) {
			printf("Bad pointer %s i=%d\n", __func__, i);
			abort();
		}
	}
	ctx_buf_mng_next_free_index = 0;

}


/**
 * Allocate per packet processing context and associate it with
 * packet buffer
 *
 * @param pkt  Packet
 *
 * @return pointer to context area
 */
static
pkt_ctx_t *alloc_pkt_ctx(odp_packet_t pkt)
{
	odp_buffer_t ctx_buf = ctx_buf_mng_db[ctx_buf_mng_next_free_index];// odp_buffer_alloc(ctx_pool);

	if (++ctx_buf_mng_next_free_index >= MAX_CTX_DB-1 ) {
		ctx_buf_mng_next_free_index = 0;
	}

	pkt_ctx_t *ctx;

	ctx = odp_buffer_addr(ctx_buf);
	memset(ctx, 0, sizeof(*ctx));
	ctx->buffer = ctx_buf;
	odp_packet_user_ptr_set(pkt, ctx);

	return ctx;
}

/**
 * Release per packet resources
 *
 * @param ctx  Packet context
 */
static
void free_pkt_ctx(pkt_ctx_t *ctx UNUSED)
{
//	odp_buffer_free(ctx->buffer);


}

/**
 * Example supports either polling queues or using odp_schedule
 */
typedef odp_queue_t (*queue_create_func_t)
		    (const char *, const odp_queue_param_t *);
typedef odp_event_t (*schedule_func_t) (odp_queue_t *);

static queue_create_func_t queue_create;
static schedule_func_t schedule;

#define MAX_POLL_QUEUES 256

static odp_queue_t poll_queues[MAX_POLL_QUEUES];
static int num_polled_queues;

/**
 * odp_queue_create wrapper to enable polling versus scheduling
 */
static
odp_queue_t polled_odp_queue_create(const char *name,
				    const odp_queue_param_t *param)
{
	odp_queue_t my_queue;
	odp_queue_param_t qp;
	odp_queue_type_t type;

	odp_queue_param_init(&qp);
	if (param)
		memcpy(&qp, param, sizeof(odp_queue_param_t));

	type = qp.type;

	if (ODP_QUEUE_TYPE_SCHED == type) {
		printf("%s: change %s to PLAIN\n", __func__, name);
		qp.type = ODP_QUEUE_TYPE_PLAIN;
	}

	my_queue = odp_queue_create(name, &qp);

	if (ODP_QUEUE_TYPE_SCHED == type) {
		poll_queues[num_polled_queues++] = my_queue;
		printf("%s: adding %"PRIu64"\n", __func__,
		       odp_queue_to_u64(my_queue));
	}

	return my_queue;
}

static inline
odp_event_t odp_schedule_cb(odp_queue_t *from)
{
	return odp_schedule(from, ODP_SCHED_WAIT);
}

/**
 * odp_schedule replacement to poll queues versus using ODP scheduler
 */
static
odp_event_t polled_odp_schedule_cb(odp_queue_t *from)
{
	int idx = 0;

	while (1) {
		if (idx >= num_polled_queues)
			idx = 0;

		odp_queue_t queue = poll_queues[idx++];
		odp_event_t buf;

		buf = odp_queue_deq(queue);

		if (ODP_EVENT_INVALID != buf) {
			*from = queue;
			return buf;
		}
	}

	*from = ODP_QUEUE_INVALID;
	return ODP_EVENT_INVALID;
}

/**
 * IPsec pre argument processing intialization
 */
static
void ipsec_init_pre(void)
{
	odp_queue_param_t qparam;
	odp_pool_param_t params;

	/*
	 * Create queues
	 *
	 *  - completion queue (should eventually be ORDERED)
	 *  - sequence number queue (must be ATOMIC)
	 */
	odp_queue_param_init(&qparam);

	qparam.type        = ODP_QUEUE_TYPE_PLAIN;
	qparam.sched.prio  = ODP_SCHED_PRIO_HIGHEST;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	completionq = queue_create("completion", &qparam);
	if (ODP_QUEUE_INVALID == completionq) {
		EXAMPLE_ERR("Error: completion queue creation failed\n");
		exit(EXIT_FAILURE);
	}

	qparam.type        = ODP_QUEUE_TYPE_PLAIN;
	qparam.sched.prio  = ODP_SCHED_PRIO_HIGHEST;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	seqnumq = queue_create("seqnum", &qparam);
	if (ODP_QUEUE_INVALID == seqnumq) {
		EXAMPLE_ERR("Error: sequence number queue creation failed\n");
		exit(EXIT_FAILURE);
	}

	/* Create output buffer pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_OUT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_OUT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_BUF_COUNT;
	params.type        = ODP_POOL_PACKET;

	out_pool = odp_pool_create("out_pool", &params);

	if (ODP_POOL_INVALID == out_pool) {
		EXAMPLE_ERR("Error: message pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Initialize our data bases */
	init_sp_db();
	init_sa_db();
	init_tun_db();
	init_ipsec_cache();
}

/**
 * IPsec post argument processing intialization
 *
 * Resolve SP DB with SA DB and create corresponding IPsec cache entries
 *
 * @param api_mode  Mode to use when invoking per packet crypto API
 */
static
void ipsec_init_post(crypto_api_mode_e api_mode)
{
	sp_db_entry_t *entry;

	/* Attempt to find appropriate SA for each SP */
	for (entry = sp_db->list; NULL != entry; entry = entry->next) {
		sa_db_entry_t *cipher_sa = NULL;
		sa_db_entry_t *auth_sa = NULL;
		tun_db_entry_t *tun = NULL;

		if (entry->esp) {
			cipher_sa = find_sa_db_entry(&entry->src_subnet,
						     &entry->dst_subnet,
						     1);
			tun = find_tun_db_entry(cipher_sa->src_ip,
						cipher_sa->dst_ip);
		}
		if (entry->ah) {
			auth_sa = find_sa_db_entry(&entry->src_subnet,
						   &entry->dst_subnet,
						   0);
			tun = find_tun_db_entry(auth_sa->src_ip,
						auth_sa->dst_ip);
		}

		if (cipher_sa || auth_sa) {
			if (create_ipsec_cache_entry(cipher_sa,
						     auth_sa,
						     tun,
						     api_mode,
						     entry->input,
						     completionq,
						     out_pool)) {
				EXAMPLE_ERR("Error: IPSec cache entry failed.\n"
						);
				exit(EXIT_FAILURE);
			}
		} else {
			printf(" WARNING: SA not found for SP\n");
			dump_sp_db_entry(entry);
		}
	}
}

/**
 * Initialize interface
 *
 * Initialize ODP pktio and queues, query MAC address and update
 * forwarding database.
 *
 * @param intf          Interface name string
 * @param if_index      TODO
 */
static
void initialize_intf(char *intf, int if_index)
{
	odp_pktin_queue_t inq;
	odp_pktio_t pktio;
	odp_pktout_queue_t pktout;

	int ret;
	uint8_t src_mac[ODPH_ETHADDR_LEN];
	char src_mac_str[MAX_STRING];
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode  = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTIN_MODE_DIRECT;

	/*
	 * Open a packet IO instance for thread and get default output queue
	 */
	pktio = odp_pktio_open(intf, pkt_pool, &pktio_param);
	if (ODP_PKTIO_INVALID == pktio) {
		EXAMPLE_ERR("Error: pktio create failed for %s\n", intf);
		exit(EXIT_FAILURE);
	}

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;

	pktin_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
	pktin_param.hash_enable = 1;
	pktin_param.hash_proto.proto.ipv4 = 1;
	pktin_param.hash_proto.proto.ipv4_tcp = 1;
	pktin_param.hash_proto.proto.ipv4_udp = 1;
	pktin_param.num_queues = 1;

	if (odp_pktin_queue_config(pktio, &pktin_param)) {
		EXAMPLE_ERR("Error: pktin config failed for %s\n", intf);
		exit(EXIT_FAILURE);
	}

	if (odp_pktout_queue_config(pktio, NULL)) {
		EXAMPLE_ERR("Error: pktout config failed for %s\n", intf);
		exit(EXIT_FAILURE);
	}

	if (odp_pktin_queue(pktio, &inq, 1) != 1) {
		EXAMPLE_ERR("Error: failed to get input queue for %s\n", intf);
		exit(EXIT_FAILURE);
	}

	odp_pktout_queue_param_t out_queue_param;
	odp_pktout_queue_param_init(&out_queue_param);
	out_queue_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
	out_queue_param.num_queues = 1;
	if (odp_pktout_queue_config(pktio, &out_queue_param)) {
	      EXAMPLE_ERR("Error: failed to get pktout queue for %s\n", intf);
	}

	if (odp_pktout_queue(pktio, &pktout, 1) != 1) {
		EXAMPLE_ERR("Error: failed to get pktout queue for %s\n", intf);
		exit(EXIT_FAILURE);
	}

	ret = odp_pktio_start(pktio);
	if (ret) {
		EXAMPLE_ERR("Error: unable to start %s\n", intf);
		exit(EXIT_FAILURE);
	}

	/* Read the source MAC address for this interface */
	ret = odp_pktio_mac_addr(pktio, src_mac, sizeof(src_mac));
	if (ret <= 0) {
		EXAMPLE_ERR("Error: failed during MAC address get for %s\n",
			    intf);
		exit(EXIT_FAILURE);
	}

	printf("Created pktio:%02" PRIu64 ", queue mode (ATOMIC queues)\n"
	   "		  default pktio%02" PRIu64 "\n"
	   "		  source mac address %s\n",
	   odp_pktio_to_u64(pktio),
	   odp_pktio_to_u64(pktio),
	   mac_addr_str(src_mac_str, src_mac));

	port_io_config[if_index].pktio    = pktio;
	port_io_config[if_index].ifin[0]  = inq;
	port_io_config[if_index].ifout[0] = pktout;

	/* Resolve any routes using this interface for output */
	resolve_fwd_db(intf, pktout, src_mac);
}

/**
 * Packet Processing - Input verification
 *
 * @param pkt  Packet to inspect
 * @param ctx  Packet process context (not used)
 *
 * @return PKT_CONTINUE if good, supported packet else PKT_DROP
 */
static
pkt_disposition_e do_input_verify(odp_packet_t pkt,
				  pkt_ctx_t *ctx EXAMPLE_UNUSED)
{
	if (odp_unlikely(odp_packet_has_error(pkt)))
		return PKT_DROP;

	if (!odp_packet_has_eth(pkt))
		return PKT_DROP;

	if (!odp_packet_has_ipv4(pkt))
		return PKT_DROP;

	return PKT_CONTINUE;
}

/**
 * Packet Processing - Route lookup in forwarding database
 *
 * @param pkt  Packet to route
 * @param ctx  Packet process context
 *
 * @return PKT_CONTINUE if route found else PKT_DROP
 */
static
pkt_disposition_e do_route_fwd_db(odp_packet_t pkt, pkt_ctx_t *ctx)
{
	odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	fwd_db_entry_t *entry;

	entry = find_fwd_db_entry(odp_be_to_cpu_32(ip->dst_addr));

	if (entry) {
		odph_ethhdr_t *eth =
			(odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);

		memcpy(&eth->dst, entry->dst_mac, ODPH_ETHADDR_LEN);
		memcpy(&eth->src, entry->src_mac, ODPH_ETHADDR_LEN);
		ctx->pktout = entry->pktout;

		return PKT_CONTINUE;
	}

	return PKT_DROP;
}

/**
 * Packet Processing - Input IPsec packet classification
 *
 * Verify the received packet has IPsec headers and a match
 * in the IPsec cache, if so issue crypto request else skip
 * input crypto.
 *
 * @param pkt   Packet to classify
 * @param ctx   Packet process context
 * @param skip  Pointer to return "skip" indication
 *
 * @return PKT_CONTINUE if done else PKT_POSTED
 */
static
pkt_disposition_e do_ipsec_in_classify(odp_packet_t pkt,
				       pkt_ctx_t *ctx,
				       odp_bool_t *skip,
				       odp_crypto_op_result_t *result)
{
	uint8_t *buf = odp_packet_data(pkt);
	odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	int hdr_len;
	odph_ahhdr_t *ah = NULL;
	odph_esphdr_t *esp = NULL;
	ipsec_cache_entry_t *entry;
	odp_crypto_op_params_t params;
	odp_bool_t posted = 0;

	/* Default to skip IPsec */
	*skip = TRUE;

	/* Check IP header for IPSec protocols and look it up */
	hdr_len = locate_ipsec_headers(ip, &ah, &esp);
	if (!ah && !esp) {
		dprintf("%s 1   not AH and not ESP\n",  __func__);
		return PKT_CONTINUE;
	}

	dprintf("%s 2 src %x dst %x \n", __func__, odp_be_to_cpu_32(ip->src_addr), odp_be_to_cpu_32(ip->dst_addr));

	entry = find_ipsec_cache_entry_in(odp_be_to_cpu_32(ip->src_addr),
					  odp_be_to_cpu_32(ip->dst_addr),
					  ah,
					  esp);
	if (!entry) {
		dprintf("%s 2.1 !!!  find_ipsec_cache_entry_in not found\n",  __func__);
		return PKT_CONTINUE;
	}

	/* Account for configured ESP IV length in packet */
	hdr_len += entry->esp.iv_len;

	/* Initialize parameters block */
	memset(&params, 0, sizeof(params));
	params.ctx = ctx;
	params.session = entry->state.session;
	params.pkt = pkt;
	params.out_pkt = entry->in_place ? pkt : ODP_PACKET_INVALID;

	/*Save everything to context */
	ctx->ipsec.ip_tos = ip->tos;
	ctx->ipsec.ip_frag_offset = odp_be_to_cpu_16(ip->frag_offset);
	ctx->ipsec.ip_ttl = ip->ttl;
	ctx->ipsec.ah_offset = ah ? ((uint8_t *)ah) - buf : 0;
	ctx->ipsec.esp_offset = esp ? ((uint8_t *)esp) - buf : 0;
	ctx->ipsec.hdr_len = hdr_len;
	ctx->ipsec.trl_len = 0;
	ctx->ipsec.src_ip = entry->src_ip;
	ctx->ipsec.dst_ip = entry->dst_ip;
	ctx->ipsec.auth_alg = entry->esp.auth_alg;


	/*If authenticating, zero the mutable fields build the request */
	if (ah) {
		ip->chksum = 0;
		ip->tos = 0;
		ip->frag_offset = 0;
		ip->ttl = 0;

		params.auth_range.offset = ((uint8_t *)ip) - buf;
		params.auth_range.length = odp_be_to_cpu_16(ip->tot_len);
		params.hash_result_offset = ah->icv - buf;
	}

	/* If deciphering build request */
	if (esp) {
		params.cipher_range.offset = ipv4_data_p(ip) + hdr_len - buf;
		params.cipher_range.length = ipv4_data_len(ip) - hdr_len;
		params.override_iv_ptr = esp->iv;
	}

	/* Issue crypto request */
	*skip = FALSE;
	ctx->state = PKT_STATE_IPSEC_IN_FINISH;
	int rc = odp_crypto_operation(&params,
				 &posted,
				 result);

	if ((rc != 0) || (!posted && !result->ok)) {
		dprintf("do_ipsec_in_classify 3   odp_crypto_operation failed\n");
		return PKT_DROP;
	}

	dprintf("do_ipsec_in_classify 4 finish=%d *skip=%d \n", posted, *skip);

	return (posted) ? PKT_POSTED : PKT_CONTINUE;
}

/**
 * Packet Processing - Input IPsec packet processing cleanup
 *
 * @param pkt  Packet to handle
 * @param ctx  Packet process context
 *
 * @return PKT_CONTINUE if successful else PKT_DROP
 */
static
pkt_disposition_e do_ipsec_in_finish(odp_packet_t pkt,
				     pkt_ctx_t *ctx,
				     odp_crypto_op_result_t *result)
{
	odph_ipv4hdr_t *ip;
	int hdr_len = ctx->ipsec.hdr_len;
	int trl_len = 0;
	int icv_len = 0;

	/* Check crypto result */
	if (!result->ok) {
		if (!is_crypto_compl_status_ok(&result->cipher_status))
			return PKT_DROP;
		if (!is_crypto_compl_status_ok(&result->auth_status))
			return PKT_DROP;
	}
	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);

	/*
	 * Finish auth
	 */
	if (ctx->ipsec.ah_offset) {
		uint8_t *buf = odp_packet_data(pkt);
		odph_ahhdr_t *ah;

		ah = (odph_ahhdr_t *)(ctx->ipsec.ah_offset + buf);
		ip->proto = ah->next_header;
	}

	if (ctx->ipsec.auth_alg == ODP_AUTH_ALG_MD5_96) {
		icv_len = ODP_AUTH_ALG_MD5_96_ICV_LEN; /* 12 ICV bytes  */
	}

    /*
     * Finish cipher by finding ESP trailer and processing
     *
     * NOTE: ESP authentication ICV not supported
     */
	if (ctx->ipsec.esp_offset) {
		uint8_t *eop = (uint8_t *)(ip) + odp_be_to_cpu_16(ip->tot_len) - icv_len;
		odph_esptrl_t *esp_t = (odph_esptrl_t *)(eop) - 1;

		ip->proto = esp_t->next_header;
		trl_len += esp_t->pad_len + sizeof(*esp_t) + icv_len;
	}

	/* We have a tunneled IPv4 packet */
	if (ip->proto == ODPH_IPV4) {
		odp_packet_pull_head(pkt, sizeof(*ip) + hdr_len);
		odp_packet_pull_tail(pkt, trl_len);
		odph_ethhdr_t *eth;

		eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
		eth->type = ODPH_ETHTYPE_IPV4;
		ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);

		/* Check inbound policy */
		if ((ip->src_addr != ctx->ipsec.src_ip ||
		     ip->dst_addr != ctx->ipsec.dst_ip))
			return PKT_DROP;

		return PKT_CONTINUE;
	}

	/* Finalize the IPv4 header */
	ipv4_adjust_len(ip, -(hdr_len + trl_len));
	ip->ttl = ctx->ipsec.ip_ttl;
	ip->tos = ctx->ipsec.ip_tos;
	ip->frag_offset = odp_cpu_to_be_16(ctx->ipsec.ip_frag_offset);
	ip->chksum = 0;
#if !defined(ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT) || (ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT == 0)
	odph_ipv4_csum_update(pkt);
#endif /* !defined(ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT) || ... */

	/* Correct the packet length and move payload into position */
#ifdef MEMMOVE_OPTIMIZED
	uint8_t *l2_p = odp_packet_l2_ptr(pkt, NULL);
	memmove(l2_p + hdr_len, l2_p, ipv4_data_p(ip) - l2_p);
	odp_packet_pull_head(pkt, hdr_len);
	odp_packet_pull_tail(pkt, trl_len);
#else
	memmove(ipv4_data_p(ip),
	ipv4_data_p(ip) + hdr_len,
	odp_be_to_cpu_16(ip->tot_len));
	odp_packet_pull_tail(pkt, hdr_len + trl_len);
#endif

	/* Fall through to next state */
	return PKT_CONTINUE;
}

/**
 * Packet Processing - Output IPsec packet classification
 *
 * Verify the outbound packet has a match in the IPsec cache,
 * if so issue prepend IPsec headers and prepare parameters
 * for crypto API call.  Post the packet to ATOMIC queue so
 * that sequence numbers can be applied in packet order as
 * the next processing step.
 *
 * @param pkt   Packet to classify
 * @param ctx   Packet process context
 * @param skip  Pointer to return "skip" indication
 *
 * @return PKT_CONTINUE if done else PKT_POSTED
 */
static
pkt_disposition_e do_ipsec_out_classify(odp_packet_t pkt,
					pkt_ctx_t *ctx,
					odp_bool_t *skip)
{
	uint8_t *buf = odp_packet_data(pkt);
	odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	uint16_t ip_data_len = ipv4_data_len(ip);
	uint8_t *ip_data = ipv4_data_p(ip);
	ipsec_cache_entry_t *entry;
	odp_crypto_op_params_t params;
	int hdr_len = 0;
	int trl_len = 0;
	odph_ahhdr_t *ah = NULL;
	odph_esphdr_t *esp = NULL;
	int icv_len = 0;


	/* Default to skip IPsec */
	*skip = TRUE;

	/* Find record */
	entry = find_ipsec_cache_entry_out(odp_be_to_cpu_32(ip->src_addr),
					   odp_be_to_cpu_32(ip->dst_addr),
					   ip->proto);
	if (!entry) {
		dprintf("out_classify %s find_ipsec_cache_entry_out failed\n", __func__ );
		return PKT_CONTINUE;
	}

	/* Save IPv4 stuff */
	ctx->ipsec.ip_tos = ip->tos;
	ctx->ipsec.ip_frag_offset = odp_be_to_cpu_16(ip->frag_offset);
	ctx->ipsec.ip_ttl = ip->ttl;

	/* Initialize parameters block */
	memset(&params, 0, sizeof(params));
	params.session = entry->state.session;
	params.ctx = ctx;
	params.pkt = pkt;
	params.out_pkt = entry->in_place ? pkt : ODP_PACKET_INVALID;

	if (entry->mode == IPSEC_SA_MODE_TUNNEL) {
		hdr_len += sizeof(odph_ipv4hdr_t);
		ip_data = (uint8_t *)ip;
		ip_data_len += sizeof(odph_ipv4hdr_t);
	}
	/* Compute ah and esp, determine length of headers, move the data */
	if (entry->ah.alg) {
		ah = (odph_ahhdr_t *)(ip_data + hdr_len);
		hdr_len += sizeof(odph_ahhdr_t);
		hdr_len += entry->ah.icv_len;
	}
	if (entry->esp.alg) {
		esp = (odph_esphdr_t *)(ip_data + hdr_len);
		hdr_len += sizeof(odph_esphdr_t);
		hdr_len += entry->esp.iv_len;
		ctx->ipsec.auth_alg = entry->esp.auth_alg;
	}

#ifdef MEMMOVE_OPTIMIZED
	uint8_t *l2_p = odp_packet_l2_ptr(pkt, NULL);
	uint16_t move_size = ip_data - l2_p;	/* use not updated l2_ptr  */
	odp_packet_push_head(pkt, hdr_len);
	memmove(l2_p - hdr_len, l2_p, move_size);
	/* update local pointers */
	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	esp = (odph_esphdr_t *)ipv4_data_p(ip);
	buf -= hdr_len;
#else
	memmove(ip_data + hdr_len, ip_data, ip_data_len);
	ip_data += hdr_len;
#endif

	/* update outer header in tunnel mode */
	if (entry->mode == IPSEC_SA_MODE_TUNNEL) {
		/* tunnel addresses */
		ip->src_addr = odp_cpu_to_be_32(entry->tun_src_ip);
		ip->dst_addr = odp_cpu_to_be_32(entry->tun_dst_ip);
	}

	/* For cipher, compute encrypt length, build headers and request */
	if (esp) {
		uint32_t encrypt_len;
		odph_esptrl_t *esp_t;

		encrypt_len = ESP_ENCODE_LEN(ip_data_len +
					     sizeof(*esp_t),
					     entry->esp.block_len);
		trl_len = encrypt_len - ip_data_len;

		if (ctx->ipsec.auth_alg == ODP_AUTH_ALG_MD5_96) {
			icv_len = ODP_AUTH_ALG_MD5_96_ICV_LEN;
		}

		esp->spi = odp_cpu_to_be_32(entry->esp.spi);
		memcpy(esp + 1, entry->state.iv, entry->esp.iv_len);

		esp_t = (odph_esptrl_t *)(ip_data + encrypt_len) - 1;
		esp_t->pad_len     = trl_len - sizeof(*esp_t);
		if (entry->mode == IPSEC_SA_MODE_TUNNEL)
			esp_t->next_header = ODPH_IPV4;
		else
			esp_t->next_header = ip->proto;
		ip->proto = ODPH_IPPROTO_ESP;

		params.cipher_range.offset = ip_data - buf;
		params.cipher_range.length = encrypt_len;
	}

	/* For authentication, build header clear mutables and build request */
	if (ah) {
		memset(ah, 0, sizeof(*ah) + entry->ah.icv_len);
		ah->spi = odp_cpu_to_be_32(entry->ah.spi);
		ah->ah_len = 1 + (entry->ah.icv_len / 4);
		if (entry->mode == IPSEC_SA_MODE_TUNNEL && !esp)
			ah->next_header = ODPH_IPV4;
		else
			ah->next_header = ip->proto;
		ip->proto = ODPH_IPPROTO_AH;

		ip->chksum = 0;
		ip->tos = 0;
		ip->frag_offset = 0;
		ip->ttl = 0;

		params.auth_range.offset = ((uint8_t *)ip) - buf;
		params.auth_range.length =
			odp_be_to_cpu_16(ip->tot_len) + (hdr_len + trl_len);
		params.hash_result_offset = ah->icv - buf;
	}

	/* Set IPv4 length before authentication */
	ipv4_adjust_len(ip, hdr_len + trl_len + icv_len);

#ifdef MEMMOVE_OPTIMIZED
	if (!odp_packet_push_tail(pkt, trl_len + icv_len)) {
#else
	if (!odp_packet_push_tail(pkt, hdr_len + trl_len + icv_len)) {
#endif
		dprintf("out_classify %s odp_packet_push_tail failed PKT_DROP\n", __func__ );
		return PKT_DROP;
	}

	/* Save remaining context */
	ctx->ipsec.hdr_len = hdr_len;
	ctx->ipsec.trl_len = trl_len;
	ctx->ipsec.ah_offset = ah ? ((uint8_t *)ah) - buf : 0;
	ctx->ipsec.esp_offset = esp ? ((uint8_t *)esp) - buf : 0;
	ctx->ipsec.tun_hdr_offset = (entry->mode == IPSEC_SA_MODE_TUNNEL) ?
				       ((uint8_t *)ip - buf) : 0;
	ctx->ipsec.ah_seq = &entry->state.ah_seq;
	ctx->ipsec.esp_seq = &entry->state.esp_seq;
	ctx->ipsec.tun_hdr_id = &entry->state.tun_hdr_id;
	memcpy(&ctx->ipsec.params, &params, sizeof(params));

	*skip = FALSE;

	dprintf("out_classify %s ok status PKT_POSTED, skip FALSE \n", __func__);

	return PKT_POSTED;
}

/**
 * Packet Processing - Output IPsec packet sequence number assignment
 *
 * Assign the necessary sequence numbers and then issue the crypto API call
 *
 * @param pkt  Packet to handle
 * @param ctx  Packet process context
 *
 * @return PKT_CONTINUE if done else PKT_POSTED
 */
static
pkt_disposition_e do_ipsec_out_seq(odp_packet_t pkt,
				   pkt_ctx_t *ctx,
				   odp_crypto_op_result_t *result)
{
	uint8_t *buf = odp_packet_data(pkt);
	odp_bool_t posted = 0;

	/* We were dispatched from atomic queue, assign sequence numbers */
	if (ctx->ipsec.ah_offset) {
		odph_ahhdr_t *ah;

		ah = (odph_ahhdr_t *)(ctx->ipsec.ah_offset + buf);
		ah->seq_no = odp_cpu_to_be_32((*ctx->ipsec.ah_seq)++);
	}
	if (ctx->ipsec.esp_offset) {
		odph_esphdr_t *esp;

		esp = (odph_esphdr_t *)(ctx->ipsec.esp_offset + buf);
		esp->seq_no = odp_cpu_to_be_32((*ctx->ipsec.esp_seq)++);
		/* TBD: ctx->ipsec.params.override_iv_ptr = esp->iv; */
	}
	if (ctx->ipsec.tun_hdr_offset) {
		odph_ipv4hdr_t *ip;
		int ret;

		ip = (odph_ipv4hdr_t *)(ctx->ipsec.tun_hdr_offset + buf);
		ip->id = odp_cpu_to_be_16((*ctx->ipsec.tun_hdr_id)++);
		if (!ip->id) {
			/* re-init tunnel hdr id */
			ret = odp_random_data((uint8_t *)ctx->ipsec.tun_hdr_id,
					      sizeof(*ctx->ipsec.tun_hdr_id),
					      1);
			if (ret != sizeof(*ctx->ipsec.tun_hdr_id))
				abort();
		}
	}

	/* Issue crypto request */
	int rc = odp_crypto_operation(&ctx->ipsec.params,
				 &posted,
				 result);
	if ((rc != 0) || (!posted && !result->ok)) {
		return PKT_DROP;
	}
	return (posted) ? PKT_POSTED : PKT_CONTINUE;
}

/**
 * Packet Processing - Output IPsec packet processing cleanup
 *
 * @param pkt  Packet to handle
 * @param ctx  Packet process context
 *
 * @return PKT_CONTINUE if successful else PKT_DROP
 */
static
pkt_disposition_e do_ipsec_out_finish(odp_packet_t pkt,
				      pkt_ctx_t *ctx,
				      odp_crypto_op_result_t *result)
{
	odph_ipv4hdr_t *ip;

	/* Check crypto result */
	if (!result->ok) {
		if (!is_crypto_compl_status_ok(&result->cipher_status))
			return PKT_DROP;
		if (!is_crypto_compl_status_ok(&result->auth_status))
			return PKT_DROP;
	}
	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);

	/* Finalize the IPv4 header */
	ip->ttl = ctx->ipsec.ip_ttl;
	ip->tos = ctx->ipsec.ip_tos;
	ip->frag_offset = odp_cpu_to_be_16(ctx->ipsec.ip_frag_offset);
	ip->chksum = 0;
#if !defined(ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT) || (ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT == 0)
	odph_ipv4_csum_update(pkt);
#endif /* !defined(ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT) || ... */

	/* Fall through to next state */
	return PKT_CONTINUE;
}


static odp_event_t  after_crypto_events[MAX_PKT_BURST];
static odp_packet_t after_crypto_pkt_outgoing[MAX_PKT_BURST];
static odp_packet_t after_crypto_pkt_ingoing[MAX_PKT_BURST];
static pkt_ctx_t	*after_crypto_ctx[MAX_PKT_BURST];

static
int crypto_rx_handler(void)
{

	int pkt_index;
	pkt_disposition_e rc = 0;
	odp_crypto_op_result_t result;
	int after_crypto_pkt_outgoing_index = 0;
	int after_crypto_pkt_ingoing_index = 0;
	int after_crypto_pkts;
	odp_pktout_queue_t output_outgoing_queue;
	odp_pktout_queue_t output_ingoing_queue;
	

	/* Encryption: src_port = 0;  dsp_port = 1; Decryption:  src_port = 1;	dsp_port = 0; - for demo only  */

	/* FROM CRYPTO */
	after_crypto_pkts = odp_queue_deq_multi(completionq, after_crypto_events, MAX_PKT_BURST);
	if (after_crypto_pkts < 1) {
		return 0;
	}

	for (pkt_index = 0; pkt_index < after_crypto_pkts; pkt_index++) {
		odp_crypto_compl_t compl;

		compl = odp_crypto_compl_from_event(after_crypto_events[pkt_index]);
		odp_crypto_compl_result(compl, &result);
		odp_crypto_compl_free(compl);
		after_crypto_ctx[pkt_index] = result.ctx;

		dprintf("AFTER CRYPTO after_crypto_pkts %d\n", after_crypto_pkts);

		if (PKT_STATE_IPSEC_IN_FINISH == after_crypto_ctx[pkt_index]->state) {    /* Decryption */
			dprintf("ODP Main Loop 6: Decryption odp_packet_from_event rc=%d state=%d  packet=%d\n", rc, after_crypto_ctx[pkt_index]->state, pkt_index);
		
			after_crypto_pkt_ingoing[after_crypto_pkt_ingoing_index] = result.pkt;

			/* Handle decryption  */

			rc = do_ipsec_in_finish(after_crypto_pkt_ingoing[after_crypto_pkt_ingoing_index], after_crypto_ctx[pkt_index], &result);
			if (odp_unlikely(rc == PKT_DROP)) {
				odp_packet_free(after_crypto_pkt_ingoing[after_crypto_pkt_ingoing_index]);
				continue;
			}

			dprintf("ODP Main Loop 14: do_ipsec_in_finish packet=%d\n", pkt_index);

			rc = do_route_fwd_db(after_crypto_pkt_ingoing[after_crypto_pkt_ingoing_index], after_crypto_ctx[pkt_index]);
			if (odp_unlikely(rc == PKT_DROP)) {
				odp_packet_free(after_crypto_pkt_ingoing[after_crypto_pkt_ingoing_index]);
				continue;
			}

			output_ingoing_queue = after_crypto_ctx[pkt_index]->pktout;  /* take output queue after forwarding decision */

			after_crypto_pkt_ingoing_index++;

			dprintf("ODP Main Loop 15: do_route_fwd_db packet=%d\n", pkt_index);
		} else {   /* Encryption */
			dprintf("ODP Main Loop 7: Encryption odp_packet_from_event state=%d  packet=%d\n", after_crypto_ctx[pkt_index]->state, pkt_index);

			after_crypto_pkt_outgoing[after_crypto_pkt_outgoing_index] = result.pkt;
			output_outgoing_queue = after_crypto_ctx[pkt_index]->pktout;

			/* Handle Encryption */
			rc = do_ipsec_out_finish(after_crypto_pkt_outgoing[after_crypto_pkt_outgoing_index], after_crypto_ctx[pkt_index], &result);

			dprintf("ODP Main Loop 10: do_ipsec_out_finish rc=%d result=%d\n", rc, result.ok);

			if (odp_unlikely(rc == PKT_DROP)) {
				odp_packet_free(after_crypto_pkt_outgoing[after_crypto_pkt_outgoing_index]);
				continue;
			}

			after_crypto_pkt_outgoing_index++;
		}
	}

	int sent_encrypted = 0;
	if (after_crypto_pkt_outgoing_index) {
		sent_encrypted = odp_pktout_send(output_outgoing_queue, after_crypto_pkt_outgoing, after_crypto_pkt_outgoing_index);
		dprintf("ODP Main Loop 11: TX outgoing sent=%d from %d\n", sent_encrypted, after_crypto_pkt_outgoing_index);
	}

	int sent_decrypted = 0;
	if (after_crypto_pkt_ingoing_index) {
		sent_decrypted += odp_pktout_send(output_ingoing_queue, after_crypto_pkt_ingoing, after_crypto_pkt_ingoing_index);
		dprintf("ODP Main Loop 12: TX ingoing sent=%d from %d\n", sent_decrypted, after_crypto_pkt_ingoing_index);
	}
	return sent_decrypted + sent_encrypted;

}

static
void network_rx_handler(odp_packet_t *pkt_tbl, int pkts) {

	int pkt_index;
	pkt_ctx_t	*ctx[MAX_PKT_BURST];
	pkt_disposition_e rc;
	odp_crypto_op_result_t result;
	odp_bool_t skip = FALSE;

	dprintf("ODP Main Loop 0: odp_pktin_recv  pkts=%d\n", pkts);

	for (pkt_index = 0; pkt_index < pkts; pkt_index++) {
#ifdef USE_APP_PREFETCH
		if (pkts-pkt_index > PREFETCH_SHIFT)
			odp_packet_prefetch(pkt_tbl[pkt_index+PREFETCH_SHIFT], 0, ODPH_ETHHDR_LEN);
#endif /* USE_APP_PREFETCH */
		ctx[pkt_index] = alloc_pkt_ctx(pkt_tbl[pkt_index]);
		rc = do_input_verify(pkt_tbl[pkt_index], ctx[pkt_index]);
		CHECK_RC(rc, ctx, pkt_tbl, pkt_index, 1);

		dprintf("ODP Main Loop 1: do_input_verify rc=%d\n", rc);

		ctx[pkt_index]->state = PKT_STATE_ROUTE_LOOKUP;
		rc = do_ipsec_in_classify(pkt_tbl[pkt_index], ctx[pkt_index], &skip, &result);
		CHECK_RC(rc, ctx, pkt_tbl, pkt_index, 2);

		dprintf("ODP Main Loop 2: do_ipsec_in_classify rc=%d state=%d  packet=%d\n", rc, ctx[pkt_index]->state, pkt_index);

		if (PKT_STATE_ROUTE_LOOKUP == ctx[pkt_index]->state) {
			/* ////////////////////Encryption Before Crypto/////////////// */
			rc = do_route_fwd_db(pkt_tbl[pkt_index], ctx[pkt_index]);
			CHECK_RC(rc, ctx, pkt_tbl, pkt_index, 3);

			dprintf("ODP Main Loop 3: do_route_fwd_db rc=%d state=%d  packet=%d\n", rc, ctx[pkt_index]->state, pkt_index);

			ctx[pkt_index]->state = PKT_STATE_IPSEC_OUT_CLASSIFY;

			rc = do_ipsec_out_classify(pkt_tbl[pkt_index],ctx[pkt_index],&skip);
			CHECK_RC(rc, ctx, pkt_tbl, pkt_index, 4);

			dprintf("ODP Main Loop 4: do_ipsec_out_classify rc=%d state=%d  packet=%d\n", rc, ctx[pkt_index]->state, pkt_index);

			if (odp_unlikely(skip)) {
				dprintf("ODP Main Loop 4.1: !!! Jump to TX rc=%d state=%d	packet=%d\n", rc, ctx[pkt_index]->state, pkt_index);
				continue; /*  ctx->state = PKT_STATE_TRANSMIT;   packet will be sent */
			}
			/* else {
			//	ctx[i]->state = PKT_STATE_IPSEC_OUT_SEQ;
			//	if (odp_queue_enq(seqnumq, ev))    // not clear why need seqnumq enq
			//		rc = PKT_DROP;
			} */

			/* under PKT_STATE_IPSEC_OUT_SEQ  */
			ctx[pkt_index]->state = PKT_STATE_IPSEC_OUT_FINISH;
			rc = do_ipsec_out_seq(pkt_tbl[pkt_index], ctx[pkt_index], &result);
			CHECK_RC(rc, ctx, pkt_tbl, pkt_index, 5);

			dprintf("ODP Main Loop 5: do_ipsec_out_classify rc=%d state=%d	packet=%d\n", rc, ctx[pkt_index]->state, pkt_index);

			continue;  /* handle next packet */
		}
		else {
			/* ////////////////////Decryption Phase1 - nothing to do, the packet will be handled after receiving from CRYPTO engine/////////////// */
		}
	}
}


/**
 * Packet IO worker thread
 *
 * Loop calling odp_schedule to obtain packets from one of three sources,
 * and continue processing the packet based on the state stored in its
 * per packet context.
 *
 *  - Input interfaces (i.e. new work)
 *  - Sequence number assignment queue
 *  - Per packet crypto API completion queue
 *
 * @param arg  Required by "odph_odpthreads_create", unused
 *
 * @return NULL (should never return)
 */
static
int pktio_thread(void *arg EXAMPLE_UNUSED)
{
	odp_pktin_queue_t inq;
	odp_pktin_queue_t input_queues[MAX_NB_QUEUE];
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	int pkts;
	int port = 0;
	int num_pktio = 0;
	int empty_rx_counters = 0;


	ctx_buf_mng_init();

	num_pktio = args->appl.if_count;

	if (num_pktio == 0) {
		dprintf("No pktio devices found\n");
		abort();
	}

	/* Copy all required handles to local memory */
	for (int i = 0; i < num_pktio; i++) {
		inq = port_io_config[i].ifin[0];
		input_queues[i] = inq;
	}

	odp_barrier_wait(&sync_barrier);

	/* Loop packets */
	port = 0;
	for (;;) {

		if (num_pktio > 1) {
			inq = input_queues[port];
			port++;
			if (port == num_pktio)
				port = 0;
		}

		pkts = odp_pktin_recv(inq, pkt_tbl, MAX_PKT_BURST);
		if (pkts < 1) {
			empty_rx_counters++;
			if ( empty_rx_counters > EMPTY_RX_THRESHOULD ) {
				odp_crypto_operation(NULL, NULL, NULL);
				empty_rx_counters = 0;
				crypto_rx_handler(); 
			}
			continue;
		}

		empty_rx_counters = 0;

		network_rx_handler(pkt_tbl, pkts);

		crypto_rx_handler();
	}

	/* unreachable */
	return 0;
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *token;
	size_t len;
	int rc = 0;
	int i;

	static const struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"mode", required_argument, NULL, 'm'},		/* return 'm' */
		{"route", required_argument, NULL, 'r'},	/* return 'r' */
		{"policy", required_argument, NULL, 'p'},	/* return 'p' */
		{"ah", required_argument, NULL, 'a'},		/* return 'a' */
		{"esp", required_argument, NULL, 'e'},		/* return 'e' */
		{"tunnel", required_argument, NULL, 't'},       /* return 't' */
		{"stream", required_argument, NULL, 's'},	/* return 's' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:i:m:h:r:p:a:e:t:s:";

	/* let helper collect its own arguments (e.g. --odph_proc) */
	odph_parse_options(argc, argv, shortopts, longopts);

	printf("\nParsing command line options\n");

	appl_args->mode = 0;  /* turn off async crypto API by default */

	opterr = 0; /* do not issue errors on helper options */

	while (!rc) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (-1 == opt)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->cpu_count = atoi(optarg);
			break;
			/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (0 == len) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->if_str = malloc(len);
			if (appl_args->if_str == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token != NULL;
			     token = strtok(NULL, ","), i++)
				;

			appl_args->if_count = i;

			if (0 == appl_args->if_count) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
				calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token != NULL; token = strtok(NULL, ","), i++) {
				appl_args->if_names[i] = token;
			}
			break;

		case 'm':
			appl_args->mode = atoi(optarg);
			break;

		case 'r':
			rc = create_fwd_db_entry(optarg, appl_args->if_names,
						 appl_args->if_count);
			break;

		case 'p':
			rc = create_sp_db_entry(optarg);
			break;

		case 'a':
			rc = create_sa_db_entry(optarg, FALSE);
			break;

		case 'e':
			rc = create_sa_db_entry(optarg, TRUE);
			break;

		case 't':
			rc = create_tun_db_entry(optarg);
			break;

		case 's':
			rc = create_stream_db_entry(optarg);
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}

	if (rc) {
		printf("ERROR: failed parsing -%c option\n", opt);
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (0 == appl_args->if_count) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	int i;

	printf("\n"
	       "ODP system info\n"
	       "---------------\n"
	       "ODP API version: %s\n"
	       "CPU model:       %s\n"
	       "CPU freq (hz):   %"PRIu64"\n"
	       "Cache line size: %i\n"
	       "CPU count:       %i\n"
	       "\n",
	       odp_version_api_str(), odp_cpu_model_str(), odp_cpu_hz_max(),
	       odp_sys_cache_line_size(), odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "IF-count:        %i\n"
	       "Using IFs:      ",
	       progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);

	printf("\n");

	dump_fwd_db();
	dump_sp_db();
	dump_sa_db();
	dump_tun_db();
	printf("\n\n");
	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth1,eth2,eth3 -m 0\n"
	       "\n"
	       "OpenDataPlane example application.\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       " -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       " -m, --mode   0: SYNC\n"
	       "              1: ASYNC_IN_PLACE\n"
	       "              2: ASYNC_NEW_BUFFER\n"
	       "         Default: 0: SYNC api mode\n"
	       "\n"
	       "Routing / IPSec OPTIONS:\n"
	       " -r, --route SubNet:Intf:NextHopMAC\n"
	       " -p, --policy SrcSubNet:DstSubNet:(in|out):(ah|esp|both)\n"
	       " -e, --esp SrcIP:DstIP:alg(3des|aes128|aes128-md5|null):SPI:Key(192|128)\n"
	       " -a, --ah SrcIP:DstIP:(sha256|md5|null):SPI:Key(256|128)\n"
	       "\n"
	       "  Where: NextHopMAC is raw hex/dot notation, i.e. 03.BA.44.9A.CE.02\n"
	       "         IP is decimal/dot notation, i.e. 192.168.1.1\n"
	       "         SubNet is decimal/dot/slash notation, i.e 192.168.0.0/16\n"
	       "         SPI is raw hex, 32 bits\n"
	       "         KeyXXX is raw hex, XXX bits long\n"
	       "\n"
	       "  Examples:\n"
	       "     -r 192.168.222.0/24:p8p1:08.00.27.F5.8B.DB\n"
	       "     -p 192.168.111.0/24:192.168.222.0/24:out:esp\n"
	       "     -e 192.168.111.2:192.168.222.2:3des:201:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224\n"
	       "     -a 192.168.111.2:192.168.222.2:md5:201:a731649644c5dee92cbd9c2e7e188ee6\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -c, --count <number> CPU count.\n"
	       "  -h, --help           Display help and exit.\n"
	       " environment variables: ODP_IPSEC_USE_POLL_QUEUES\n"
	       " to enable use of poll queues instead of scheduled (default)\n"
	       "                        ODP_IPSEC_STREAM_VERIFY_MDEQ\n"
	       " to enable use of multiple dequeue for queue draining during\n"
	       " stream verification instead of single dequeue (default)\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
		);
}


/**
 * ODP ipsec example main function
 */
int
main(int argc, char *argv[])
{
	odph_odpthread_t thread_tbl[MAX_WORKERS];
	int num_workers;
	int i;
	int stream_count;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	odp_instance_t instance;
	odph_odpthread_params_t thr_params;

	/* create by default scheduled queues */    ///// ONLY IPSEC START
	queue_create = odp_queue_create;
	schedule = odp_schedule_cb;

	/* check for using poll queues */
	if (getenv("ODP_IPSEC_USE_POLL_QUEUES")) {
		queue_create = polled_odp_queue_create;
		schedule = polled_odp_schedule_cb;         ///// ONLY IPSEC END
	}

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t), ODP_CACHE_LINE_SIZE,
			      0);

	args = odp_shm_addr(shm);

	if (NULL == args) {
		EXAMPLE_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(args, 0, sizeof(*args));

	/* Must init our databases before parsing args */
	ipsec_init_pre();   // create both queues, pool, init IPSEC DB
	init_fwd_db();
	init_loopback_db();
	init_stream_db();

	/* Parse and store the application arguments */
	parse_args(argc, argv, &args->appl);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &args->appl);

	/* Default to system CPU count unless user specified */
	num_workers = MAX_WORKERS;
	if (args->appl.cpu_count)
		num_workers = args->appl.cpu_count;

	/* Get default worker cpumask */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	/* Create a barrier to synchronize thread startup */
	odp_barrier_init(&sync_barrier, num_workers);

	/* Create packet buffer pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_BUF_COUNT;
	params.type        = ODP_POOL_PACKET;

	pkt_pool = odp_pool_create("packet_pool", &params);

	if (ODP_POOL_INVALID == pkt_pool) {
		EXAMPLE_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Create context buffer pool */
	params.buf.size  = SHM_CTX_POOL_BUF_SIZE;
	params.buf.align = 0;
	params.buf.num   = SHM_CTX_POOL_BUF_COUNT;
	params.type      = ODP_POOL_BUFFER;

	ctx_pool = odp_pool_create("ctx_pool", &params);

	if (ODP_POOL_INVALID == ctx_pool) {
		EXAMPLE_ERR("Error: context pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Populate our IPsec cache */
	printf("Using %s mode for crypto API\n\n",
	       (CRYPTO_API_SYNC == args->appl.mode) ? "SYNC" :
	       (CRYPTO_API_ASYNC_IN_PLACE == args->appl.mode) ?
	       "ASYNC_IN_PLACE" : "ASYNC_NEW_BUFFER");
	ipsec_init_post(args->appl.mode);

	/* Initialize interfaces (which resolves FWD DB entries */
	for (i = 0; i < args->appl.if_count; i++)
		initialize_intf(args->appl.if_names[i], i);
	if ((i%2) && (i<MAX_NB_PKTIO)) {
		port_io_config[i].pktio    = port_io_config[i-1].pktio;
		port_io_config[i].ifin[0]  = port_io_config[i-1].ifin[0];
		port_io_config[i].ifout[0] = port_io_config[i-1].ifout[0];
	}

	/* If we have test streams build them before starting workers */
	resolve_stream_db();
	stream_count = create_stream_db_inputs();

	/*
	 * Create and init worker threads
	 */
	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.start    = pktio_thread;
	thr_params.arg      = NULL;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;
	odph_odpthreads_create(thread_tbl, &cpumask, &thr_params);

	/*
	 * If there are streams attempt to verify them else
	 * wait indefinitely
	 */
	if (stream_count) {
		printf("ODP IPSEC: verify streams\n");
		odp_bool_t done;
		do {
			done = verify_stream_db_outputs();
			sleep(1);
		} while (!done);
		printf("All received\n");
	} else {
		odph_odpthreads_join(thread_tbl);
	}

	free(args->appl.if_names);
	free(args->appl.if_str);
	printf("Exit\n\n");

	return 0;
}
