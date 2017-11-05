/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/** enable strtok */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <time.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>

#include <example_debug.h>

#include <odp_api.h>

#include <odp/helper/odph_api.h>

#define MAX_WORKERS            32    /* Max number of workers */
#define POOL_NUM_PKT           2048  /* Number of packets in packet pool */
#define POOL_PKT_LEN           1856  /* Max packet length */
#define DEFAULT_PKT_INTERVAL   1000  /* Interval between each packet */
#define MAX_UDP_TX_BURST	32
#define MAX_RX_BURST		32

#define APPL_MODE_UDP    0			/**< UDP mode */
#define APPL_MODE_PING   1			/**< ping mode */
#define APPL_MODE_RCV    2			/**< receive mode */

/** print appl mode */
#define PRINT_APPL_MODE(x) printf("%s(%i)\n", #x, (x))

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

/**
 * Interfaces
 */

typedef struct {
	odp_pktio_t pktio;
	odp_pktout_queue_t pktout[MAX_WORKERS];
	unsigned pktout_count;
} interface_t;

/**
 * Parsed command line application arguments
 */
typedef struct {
	int num_workers;	/**< Number of worker thread */
	const char *mask;	/**< CPU mask */
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	char *if_str;		/**< Storage for interface names */
	odp_pool_t pool;	/**< Pool for packet IO */
	odph_ethaddr_t srcmac;	/**< src mac addr */
	odph_ethaddr_t dstmac;	/**< dest mac addr */
	unsigned int srcip;	/**< src ip addr */
	unsigned int dstip;	/**< dest ip addr */
	uint16_t srcport;	/**< src udp port */
	uint16_t dstport;	/**< dest udp port */
	int mode;		/**< work mode */
	int number;		/**< packets number to be sent */
	int payload;		/**< data len */
	int timeout;		/**< wait time */
	int interval;		/**< wait interval ms between sending
				     each packet */
	int udp_tx_burst;	/**< number of udp packets to send with one
				      API call */
} appl_args_t;

/**
 * counters
*/
static struct {
	odp_atomic_u64_t seq;	/**< ip seq to be send */
	odp_atomic_u64_t ip;	/**< ip packets */
	odp_atomic_u64_t udp;	/**< udp packets */
	odp_atomic_u64_t icmp;	/**< icmp packets */
	odp_atomic_u64_t cnt;	/**< sent packets*/
	odp_atomic_u64_t tx_drops; /**< packets dropped in transmit */
} counters;

/** * Thread specific arguments
 */
typedef struct {
	odp_pktout_queue_t pktout; /**< Packet output queue to use*/
	odp_pool_t pool;	/**< Pool for packet IO */
	odp_timer_pool_t tp;	/**< Timer pool handle */
	odp_queue_t tq;		/**< Queue for timeouts */
	odp_timer_t tim;	/**< Timer handle */
	odp_timeout_t tmo_ev;	/**< Timeout event */
	int mode;		/**< Thread mode */
} thread_args_t;

/**
 * Grouping of both parsed CL args and thread specific args - alloc together
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];
} args_t;

/** Global pointer to args */
static args_t *args;

/** Barrier to sync threads execution */
static odp_barrier_t barrier;

/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);
static int scan_ip(char *buf, unsigned int *paddr);
static void print_global_stats(int num_workers);

/**
 * Sleep for the specified amount of milliseconds
 * Use ODP timer, busy wait until timer expired and timeout event received
 */
static void millisleep(uint32_t ms,
		       odp_timer_pool_t tp,
		       odp_timer_t tim,
		       odp_queue_t q,
		       odp_timeout_t tmo)
{
	uint64_t ticks = odp_timer_ns_to_tick(tp, 1000000ULL * ms);
	odp_event_t ev = odp_timeout_to_event(tmo);
	int rc = odp_timer_set_rel(tim, ticks, &ev);
	if (rc != ODP_TIMER_SUCCESS)
		EXAMPLE_ABORT("odp_timer_set_rel() failed\n");
	/* Spin waiting for timeout event */
	while ((ev = odp_queue_deq(q)) == ODP_EVENT_INVALID)
		(void)0;
}

/**
 * Scan ip
 * Parse ip address.
 *
 * @param buf ip address string xxx.xxx.xxx.xx
 * @param paddr ip address for odp_packet
 * @return 1 success, 0 failed
*/
static int scan_ip(char *buf, unsigned int *paddr)
{
	int part1, part2, part3, part4;
	char tail = 0;
	int field;

	if (buf == NULL)
		return 0;

	field = sscanf(buf, "%d . %d . %d . %d %c",
		       &part1, &part2, &part3, &part4, &tail);

	if (field < 4 || field > 5) {
		printf("expect 4 field,get %d/n", field);
		return 0;
	}

	if (tail != 0) {
		printf("ip address mixed with non number/n");
		return 0;
	}

	if ((part1 >= 0 && part1 <= 255) && (part2 >= 0 && part2 <= 255) &&
	    (part3 >= 0 && part3 <= 255) && (part4 >= 0 && part4 <= 255)) {
		if (paddr)
			*paddr = part1 << 24 | part2 << 16 | part3 << 8 | part4;
		return 1;
	} else {
		printf("not good ip %d:%d:%d:%d/n", part1, part2, part3, part4);
	}

	return 0;
}

/**
 * set up an udp packet reference
 *
 * @param pool Buffer pool to create packet in
 *
 * @return Handle of created packet
 * @retval ODP_PACKET_INVALID  Packet could not be created
 */
static odp_packet_t setup_udp_pkt_ref(odp_pool_t pool)
{
	odp_packet_t pkt;
	char *buf;
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;

	pkt = odp_packet_alloc(pool, args->appl.payload + ODPH_UDPHDR_LEN +
			       ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN);

	if (pkt == ODP_PACKET_INVALID)
		return pkt;

	buf = odp_packet_data(pkt);

	/* ether */
	odp_packet_l2_offset_set(pkt, 0);
	eth = (odph_ethhdr_t *)buf;
	memcpy((char *)eth->src.addr, args->appl.srcmac.addr, ODPH_ETHADDR_LEN);
	memcpy((char *)eth->dst.addr, args->appl.dstmac.addr, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);

	/* ip */
	odp_packet_l3_offset_set(pkt, ODPH_ETHHDR_LEN);
	odp_packet_has_ipv4_set(pkt, 1);
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	ip->dst_addr = odp_cpu_to_be_32(args->appl.dstip);
	ip->src_addr = odp_cpu_to_be_32(args->appl.srcip);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->tot_len = odp_cpu_to_be_16(args->appl.payload + ODPH_UDPHDR_LEN +
				       ODPH_IPV4HDR_LEN);
	ip->proto = ODPH_IPPROTO_UDP;
	ip->id = 0;
	ip->ttl = 64;
	ip->chksum = 0;

	/* udp */
	odp_packet_l4_offset_set(pkt, ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	odp_packet_has_udp_set(pkt, 1);
	udp = (odph_udphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp->src_port = odp_cpu_to_be_16(args->appl.srcport);
	udp->dst_port = odp_cpu_to_be_16(args->appl.dstport);
	udp->length = odp_cpu_to_be_16(args->appl.payload + ODPH_UDPHDR_LEN);
	udp->chksum = 0;
	udp->chksum = odph_ipv4_udp_chksum(pkt);

	return pkt;
}

/**
 * set up an udp packet
 *
 * @param pool Buffer pool to create packet in
 * @param pkt_ref Reference UDP packet
 *
 * @return Handle of created packet
 * @retval ODP_PACKET_INVALID  Packet could not be created
 */
static odp_packet_t pack_udp_pkt(odp_pool_t pool, odp_packet_t pkt_ref)
{
	odp_packet_t pkt;
	char *buf;
	odph_ipv4hdr_t *ip;
	unsigned short seq;

	pkt = odp_packet_alloc(pool, args->appl.payload + ODPH_UDPHDR_LEN +
			       ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN);

	if (pkt == ODP_PACKET_INVALID)
		return pkt;

	buf = (char *)odp_packet_data(pkt);
	odp_memcpy(buf, odp_packet_data(pkt_ref),
		   args->appl.payload + ODPH_UDPHDR_LEN +
		   ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN);

	/*Update IP ID and checksum*/
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	seq = odp_atomic_fetch_add_u64(&counters.seq, 1) % 0xFFFF;
	ip->id = odp_cpu_to_be_16(seq);
	ip->chksum = odph_chksum(ip, ODPH_IPV4HDR_LEN);

	return pkt;
}

/**
 * Set up an icmp packet reference
 *
 * @param pool Buffer pool to create packet in
 *
 * @return Handle of created packet
 * @retval ODP_PACKET_INVALID  Packet could not be created
 */
static odp_packet_t setup_icmp_pkt_ref(odp_pool_t pool)
{
	odp_packet_t pkt;
	char *buf;
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	odph_icmphdr_t *icmp;

	args->appl.payload = 56;
	pkt = odp_packet_alloc(pool, args->appl.payload + ODPH_ICMPHDR_LEN +
		ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN);

	if (pkt == ODP_PACKET_INVALID)
		return pkt;

	buf = odp_packet_data(pkt);

	/* ether */
	odp_packet_l2_offset_set(pkt, 0);
	eth = (odph_ethhdr_t *)buf;
	memcpy((char *)eth->src.addr, args->appl.srcmac.addr, ODPH_ETHADDR_LEN);
	memcpy((char *)eth->dst.addr, args->appl.dstmac.addr, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);
	/* ip */
	odp_packet_l3_offset_set(pkt, ODPH_ETHHDR_LEN);
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	ip->dst_addr = odp_cpu_to_be_32(args->appl.dstip);
	ip->src_addr = odp_cpu_to_be_32(args->appl.srcip);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->ttl = 64;
	ip->tot_len = odp_cpu_to_be_16(args->appl.payload + ODPH_ICMPHDR_LEN +
				       ODPH_IPV4HDR_LEN);
	ip->proto = ODPH_IPPROTO_ICMPV4;
	ip->id = 0;
	ip->chksum = 0;

	/* icmp */
	icmp = (odph_icmphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = 0;
	icmp->un.echo.sequence = 0;
	icmp->chksum = 0;

	return pkt;
}

/**
 * Set up an icmp packet
 *
 * @param pool Buffer pool to create packet in
 * @param pkt_ref Reference ICMP packet
 *
 * @return Handle of created packet
 * @retval ODP_PACKET_INVALID  Packet could not be created
 */
static odp_packet_t pack_icmp_pkt(odp_pool_t pool, odp_packet_t pkt_ref)
{
	odp_packet_t pkt;
	char *buf;
	odph_ipv4hdr_t *ip;
	odph_icmphdr_t *icmp;
	uint64_t tval;
	uint8_t *tval_d;
	unsigned short seq;

	pkt = odp_packet_alloc(pool, args->appl.payload + ODPH_ICMPHDR_LEN +
			       ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN);

	if (pkt == ODP_PACKET_INVALID)
		return pkt;

	buf = (char *)odp_packet_data(pkt);
	odp_memcpy(buf, odp_packet_data(pkt_ref),
		   args->appl.payload + ODPH_ICMPHDR_LEN +
		   ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN);

	/* ip */
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	seq = odp_atomic_fetch_add_u64(&counters.seq, 1) % 0xffff;
	ip->id = odp_cpu_to_be_16(seq);
	ip->chksum = odph_chksum(ip, ODPH_IPV4HDR_LEN);

	/* icmp */
	icmp = (odph_icmphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	icmp->un.echo.sequence = ip->id;

	tval_d = (uint8_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN +
				  ODPH_ICMPHDR_LEN);
	tval = odp_time_to_ns(odp_time_local());
	memcpy(tval_d, &tval, sizeof(uint64_t));

	icmp->chksum = 0;
	icmp->chksum = odph_chksum(icmp, args->appl.payload + ODPH_ICMPHDR_LEN);

	return pkt;
}

/**
 * Create a pktio object
 *
 * @param dev Name of device to open
 * @param pool Pool to associate with device for packet RX/TX
 *
 * @return The handle of the created pktio object.
 * @warning This routine aborts if the create is unsuccessful.
 */
static int create_pktio(const char *dev, odp_pool_t pool,
			unsigned num_rx_queues,
			unsigned num_tx_queues,
			interface_t *itf)
{
	odp_pktio_capability_t capa;
	int ret;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	odp_pktio_op_mode_t pktout_mode;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	/* Open a packet IO instance */
	itf->pktio = odp_pktio_open(dev, pool, &pktio_param);

	if (itf->pktio == ODP_PKTIO_INVALID) {
		EXAMPLE_ERR("Error: pktio create failed for %s\n", dev);
		return -1;
	}

	if (odp_pktio_capability(itf->pktio, &capa)) {
		EXAMPLE_ERR("Error: Failed to get interface capabilities %s\n",
			    dev);
		return -1;
	}
	if (num_rx_queues > capa.max_input_queues)
		num_rx_queues = capa.max_input_queues;

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.num_queues = num_rx_queues;
	pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;

	if (odp_pktin_queue_config(itf->pktio, &pktin_param)) {
		EXAMPLE_ERR("Error: pktin queue config failed for %s\n", dev);
		return -1;
	}

	pktout_mode = ODP_PKTIO_OP_MT_UNSAFE;
	if (num_tx_queues > capa.max_output_queues) {
		num_tx_queues = capa.max_output_queues;
		pktout_mode = ODP_PKTIO_OP_MT;
	}

	odp_pktout_queue_param_init(&pktout_param);
	pktout_param.num_queues = num_tx_queues;
	pktout_param.op_mode = pktout_mode;

	if (odp_pktout_queue_config(itf->pktio, &pktout_param)) {
		EXAMPLE_ERR("Error: pktout queue config failed for %s\n", dev);
		return -1;
	}

	ret = odp_pktio_start(itf->pktio);
	if (ret)
		EXAMPLE_ABORT("Error: unable to start %s\n", dev);

	itf->pktout_count = num_tx_queues;
	if (odp_pktout_queue(itf->pktio, itf->pktout, itf->pktout_count) !=
			     (int)itf->pktout_count) {
		EXAMPLE_ERR("Error: failed to get output queues for %s\n", dev);
		return -1;
	}

	printf("  created pktio:%02" PRIu64
	       ", dev:%s, queue mode (ATOMIC queues)\n"
	       "          default pktio%02" PRIu64 "\n",
	       odp_pktio_to_u64(itf->pktio), dev,
	       odp_pktio_to_u64(itf->pktio));
	fflush(NULL);

	return 0;
}

/**
 * Packet IO loopback worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */

static int gen_send_thread(void *arg)
{
	int thr;
	int ret, i;
	thread_args_t *thr_args;
	odp_pktout_queue_t pktout;
	odp_packet_t pkt_array[MAX_UDP_TX_BURST];
	int pkt_array_size;
	int burst_start, burst_size;
	odp_packet_t pkt_ref = ODP_PACKET_INVALID;

	thr = odp_thread_id();
	thr_args = arg;

	pktout = thr_args->pktout;

	if (args->appl.mode == APPL_MODE_UDP) {
		pkt_ref = setup_udp_pkt_ref(thr_args->pool);
		pkt_array_size = args->appl.udp_tx_burst;
	} else if (args->appl.mode == APPL_MODE_PING) {
		pkt_ref = setup_icmp_pkt_ref(thr_args->pool);
		pkt_array_size = 1;
	} else {
		EXAMPLE_ERR("  [%02i] Error: invalid processing mode %d\n",
			    thr, args->appl.mode);
		return -1;
	}
	if (pkt_ref == ODP_PACKET_INVALID) {
		EXAMPLE_ERR("  [%2i] Error: reference packet creation failed\n",
			    thr);
		return -1;
	}

	printf("  [%02i] created mode: SEND\n", thr);

	odp_barrier_wait(&barrier);

	for (;;) {
		if (args->appl.number != -1 &&
		    odp_atomic_fetch_add_u64(&counters.cnt, pkt_array_size) >=
				(unsigned int)args->appl.number)
			break;

		if (args->appl.mode == APPL_MODE_UDP) {
			for (i = 0; i < pkt_array_size; i++) {
				pkt_array[i] = pack_udp_pkt(thr_args->pool,
						pkt_ref);
				if (!odp_packet_is_valid(pkt_array[i]))
					break;
			}
			if (i != pkt_array_size) {
				EXAMPLE_ERR("  [%2i] alloc_multi failed\n",
					    thr);
				odp_packet_free_multi(pkt_array, i);
				break;
			}
		} else if (args->appl.mode == APPL_MODE_PING) {
			pkt_array[0] = pack_icmp_pkt(thr_args->pool, pkt_ref);
			if (!odp_packet_is_valid(pkt_array[0])) {
				EXAMPLE_ERR("  [%2i] alloc_single failed\n",
					    thr);
				break;
			}
		} else {
			break;
		}

		for (burst_start = 0, burst_size = pkt_array_size;;) {
			ret = odp_pktout_send(pktout, &pkt_array[burst_start],
					      burst_size);
			if (ret == burst_size) {
				break;
			} else if (ret >= 0 && ret < burst_size) {
				odp_atomic_add_u64(&counters.tx_drops,
						   burst_size - ret);
				burst_start += ret;
				burst_size -= ret;
				odp_time_wait_ns(ODP_TIME_MSEC_IN_NS);
				continue;
			}
			EXAMPLE_ERR("  [%02i] packet send failed\n", thr);
			odp_packet_free_multi(&pkt_array[burst_start],
					      burst_size);
			break;
		}

		if (args->appl.interval != 0) {
			printf("  [%02i] send pkt no:%ju seq %ju\n",
			       thr,
			       odp_atomic_load_u64(&counters.seq),
			       odp_atomic_load_u64(&counters.seq)%0xffff);
			millisleep(args->appl.interval,
				   thr_args->tp,
				   thr_args->tim,
				   thr_args->tq,
				   thr_args->tmo_ev);

		}
	}

	/* receive number of reply pks until timeout */
	if (args->appl.mode == APPL_MODE_PING && args->appl.number > 0) {
		while (args->appl.timeout >= 0) {
			if (odp_atomic_load_u64(&counters.icmp) >=
			    (unsigned int)args->appl.number)
				break;
			millisleep(DEFAULT_PKT_INTERVAL,
				   thr_args->tp,
				   thr_args->tim,
				   thr_args->tq,
				   thr_args->tmo_ev);
			args->appl.timeout--;
		}
	}
	odp_packet_free(pkt_ref);

	return 0;
}

/**
 * Process icmp packets
 *
 * @param  icmp icmp header address
 * @param  msg output buffer
 */

static void process_icmp_pkt(odph_icmphdr_t *icmp, char *msg)
{
	uint64_t trecv;
	uint64_t tsend;
	uint64_t rtt_ms, rtt_us;

	msg[0] = 0;

	if (icmp->type == ICMP_ECHOREPLY) {
		odp_atomic_inc_u64(&counters.icmp);

		memcpy(&tsend, (uint8_t *)icmp + ODPH_ICMPHDR_LEN,
		       sizeof(uint64_t));
		trecv = odp_time_to_ns(odp_time_local());
		rtt_ms = (trecv - tsend) / ODP_TIME_MSEC_IN_NS;
		rtt_us = (trecv - tsend) / ODP_TIME_USEC_IN_NS -
				1000 * rtt_ms;
		sprintf(msg,
			"ICMP Echo Reply seq %d time %"
			PRIu64 ".%.03" PRIu64" ms",
			odp_be_to_cpu_16(icmp->un.echo.sequence),
			rtt_ms, rtt_us);
	} else if (icmp->type == ICMP_ECHO) {
		sprintf(msg, "Icmp Echo Request");
	}
}

/**
 * Print odp packets
 *
 * @param  thr worker id
 * @param  pkt_tbl packets to be print
 * @param  len packet number
 */
static void print_pkts(int thr, odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	char *buf;
	odph_ipv4hdr_t *ip;
	odph_icmphdr_t *icmp;
	unsigned i;
	size_t offset;
	char msg[1024];

	for (i = 0; i < len; ++i) {
		pkt = pkt_tbl[i];

		/* only ip pkts */
		if (!odp_packet_has_ipv4(pkt))
			continue;

		odp_atomic_inc_u64(&counters.ip);
		buf = odp_packet_data(pkt);
		ip = (odph_ipv4hdr_t *)(buf + odp_packet_l3_offset(pkt));
		offset = odp_packet_l4_offset(pkt);

		/* udp */
		if (ip->proto == ODPH_IPPROTO_UDP) {
			odp_atomic_inc_u64(&counters.udp);
		}

		/* icmp */
		if (ip->proto == ODPH_IPPROTO_ICMPV4) {
			icmp = (odph_icmphdr_t *)(buf + offset);

			process_icmp_pkt(icmp, msg);
			printf("  [%02i] %s\n", thr, msg);
		}
	}
}

/**
 * Main receive function
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static int gen_recv_thread(void *arg)
{
	int thr;
	odp_packet_t pkts[MAX_RX_BURST], pkt;
	odp_event_t events[MAX_RX_BURST];
	int pkt_cnt, ev_cnt, i;

	thr = odp_thread_id();
	(void)arg;

	printf("  [%02i] created mode: RECEIVE\n", thr);
	odp_barrier_wait(&barrier);

	for (;;) {
		if (args->appl.number != -1 &&
		    odp_atomic_load_u64(&counters.icmp) >=
		    (unsigned int)args->appl.number) {
			break;
		}

		/* Use schedule to get buf from any input queue */
		ev_cnt = odp_schedule_multi(NULL, ODP_SCHED_WAIT,
					    events, MAX_RX_BURST);
		if (ev_cnt == 0)
			continue;
		for (i = 0, pkt_cnt = 0; i < ev_cnt; i++) {
			pkt = odp_packet_from_event(events[i]);

			/* Drop packets with errors */
			if (odp_unlikely(odp_packet_has_error(pkt))) {
				odp_packet_free(pkt);
				continue;
			}
			pkts[pkt_cnt++] = pkt;
		}

		print_pkts(thr, pkts, pkt_cnt);

		odp_packet_free_multi(pkts, pkt_cnt);
	}

	return 0;
}

/**
 * printing verbose statistics
 *
 */
static void print_global_stats(int num_workers)
{
	odp_time_t cur, wait, next;
	uint64_t pkts_snd = 0, pkts_snd_prev = 0;
	uint64_t pps_snd = 0, maximum_pps_snd = 0;
	uint64_t pkts_rcv = 0, pkts_rcv_prev = 0;
	uint64_t pps_rcv = 0, maximum_pps_rcv = 0;
	int verbose_interval = 20;
	odp_thrmask_t thrd_mask;

	odp_barrier_wait(&barrier);

	wait = odp_time_local_from_ns(verbose_interval * ODP_TIME_SEC_IN_NS);
	next = odp_time_sum(odp_time_local(), wait);

	while (odp_thrmask_worker(&thrd_mask) == num_workers) {
		if (args->appl.number != -1 &&
		    odp_atomic_load_u64(&counters.cnt) >=
		    (unsigned int)args->appl.number) {
			break;
		}

		cur = odp_time_local();
		if (odp_time_cmp(next, cur) > 0)
			continue;

		next = odp_time_sum(cur, wait);
		switch (args->appl.mode) {
		case APPL_MODE_RCV:
			pkts_rcv = odp_atomic_load_u64(&counters.ip);
			break;
		case APPL_MODE_PING:
			pkts_snd = odp_atomic_load_u64(&counters.seq);
			pkts_rcv = odp_atomic_load_u64(&counters.icmp);
			break;
		case APPL_MODE_UDP:
			pkts_snd = odp_atomic_load_u64(&counters.seq);
			break;
		default:
			continue;
		}

		pps_snd = (pkts_snd - pkts_snd_prev) / verbose_interval;
		pkts_snd_prev = pkts_snd;
		if (pps_snd > maximum_pps_snd)
			maximum_pps_snd = pps_snd;

		pps_rcv = (pkts_rcv - pkts_rcv_prev) / verbose_interval;
		pkts_rcv_prev = pkts_rcv;
		if (pps_rcv > maximum_pps_rcv)
			maximum_pps_rcv = pps_rcv;

		printf("sent: %" PRIu64 ", drops: %" PRIu64 ", "
			"send rate: %" PRIu64 " pps, "
			"max send rate: %" PRIu64 " pps, "
			"rcv: %" PRIu64 ", "
			"recv rate: %" PRIu64 " pps, "
			"max recv rate: %" PRIu64 " pps\n",
			pkts_snd, odp_atomic_load_u64(&counters.tx_drops),
			pps_snd, maximum_pps_snd,
			pkts_rcv, pps_rcv, maximum_pps_rcv);
		fflush(NULL);
	}
}

/**
 * ODP packet example main function
 */
int main(int argc, char *argv[])
{
	odph_odpthread_t thread_tbl[MAX_WORKERS];
	odp_pool_t pool;
	int num_workers;
	unsigned num_rx_queues, num_tx_queues;
	int i;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	odp_timer_pool_param_t tparams;
	odp_timer_pool_t tp;
	odp_pool_t tmop;
	odp_queue_t tq;
	odp_event_t ev;
	interface_t *ifs;
	odp_instance_t instance;
	odph_odpthread_params_t thr_params;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* init counters */
	odp_atomic_init_u64(&counters.seq, 0);
	odp_atomic_init_u64(&counters.ip, 0);
	odp_atomic_init_u64(&counters.udp, 0);
	odp_atomic_init_u64(&counters.icmp, 0);
	odp_atomic_init_u64(&counters.cnt, 0);
	odp_atomic_init_u64(&counters.tx_drops, 0);

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t),
			      ODP_CACHE_LINE_SIZE, 0);
	args = odp_shm_addr(shm);

	if (args == NULL) {
		EXAMPLE_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(args, 0, sizeof(*args));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &args->appl);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &args->appl);

	/* Default to max number of workers, unless user specified number of
	 * workers or cpumask */
	num_workers = MAX_WORKERS;
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);

	if (args->appl.num_workers) {
		/* -w option: number of workers */
		num_workers = args->appl.num_workers;
		num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	} else if (args->appl.mask) {
		/* -c option: cpumask */
		odp_cpumask_from_str(&cpumask, args->appl.mask);
		num_workers = odp_cpumask_count(&cpumask);
	}

	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);
	fflush(NULL);

	/* ping mode need two workers */
	if (args->appl.mode == APPL_MODE_PING) {
		if (num_workers < 2) {
			EXAMPLE_ERR("Need at least two worker threads\n");
			exit(EXIT_FAILURE);
		} else {
			num_workers = 2;
		}
	}

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = POOL_PKT_LEN;
	params.pkt.len     = POOL_PKT_LEN;
	params.pkt.num     = POOL_NUM_PKT;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool", &params);

	if (pool == ODP_POOL_INVALID) {
		EXAMPLE_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	/* Create timer pool */
	tparams.res_ns = 1 * ODP_TIME_MSEC_IN_NS;
	tparams.min_tmo = 0;
	tparams.max_tmo = 10000 * ODP_TIME_SEC_IN_NS;
	tparams.num_timers = num_workers; /* One timer per worker */
	tparams.priv = 0; /* Shared */
	tparams.clk_src = ODP_CLOCK_CPU;
	tp = odp_timer_pool_create("timer_pool", &tparams);
	if (tp == ODP_TIMER_POOL_INVALID) {
		EXAMPLE_ERR("Timer pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_timer_pool_start();

	/* Create timeout pool */
	odp_pool_param_init(&params);
	params.tmo.num     = tparams.num_timers; /* One timeout per timer */
	params.type	   = ODP_POOL_TIMEOUT;

	tmop = odp_pool_create("timeout_pool", &params);
	if (tmop == ODP_POOL_INVALID) {
		EXAMPLE_ERR("Error: timeout pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	ifs = malloc(sizeof(interface_t) * args->appl.if_count);

	if (args->appl.mode == APPL_MODE_PING ||
	    args->appl.mode == APPL_MODE_UDP)
		num_rx_queues = 1;
	else
		num_rx_queues = num_workers;

	if (args->appl.mode == APPL_MODE_PING ||
	    args->appl.mode == APPL_MODE_RCV)
		num_tx_queues = 1;
	else {
		num_tx_queues = num_workers / args->appl.if_count;
		if (num_workers % args->appl.if_count)
			num_tx_queues++;
	}

	for (i = 0; i < args->appl.if_count; ++i)
		if (create_pktio(args->appl.if_names[i], pool, num_rx_queues,
				 num_tx_queues, &ifs[i])) {
			EXAMPLE_ERR("Error: create interface %s failed.\n",
				    args->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}

	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));

	/* Init threads params */
	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;

	/* num workers + print thread */
	odp_barrier_init(&barrier, num_workers + 1);

	if (args->appl.mode == APPL_MODE_PING) {
		odp_cpumask_t cpu_mask;
		int cpu_first, cpu_next;

		odp_cpumask_zero(&cpu_mask);
		cpu_first = odp_cpumask_first(&cpumask);
		odp_cpumask_set(&cpu_mask, cpu_first);

		tq = odp_queue_create("", NULL);
		if (tq == ODP_QUEUE_INVALID) {
			EXAMPLE_ERR("queue_create failed\n");
			abort();
		}
		(void)args->thread[1].pktout; /* Not used*/
		args->thread[1].pool = pool;
		args->thread[1].tp = tp;
		args->thread[1].tq = tq;
		args->thread[1].tim = odp_timer_alloc(tp, tq, NULL);
		if (args->thread[1].tim == ODP_TIMER_INVALID) {
			EXAMPLE_ERR("timer_alloc failed\n");
			abort();
		}
		args->thread[1].tmo_ev = odp_timeout_alloc(tmop);
		if (args->thread[1].tmo_ev == ODP_TIMEOUT_INVALID) {
			EXAMPLE_ERR("timeout_alloc failed\n");
			abort();
		}
		args->thread[1].mode = args->appl.mode;

		memset(&thr_params, 0, sizeof(thr_params));
		thr_params.start    = gen_recv_thread;
		thr_params.arg      = &args->thread[1];
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = instance;

		odph_odpthreads_create(&thread_tbl[1], &cpu_mask, &thr_params);

		tq = odp_queue_create("", NULL);
		if (tq == ODP_QUEUE_INVALID) {
			EXAMPLE_ERR("queue_create failed\n");
			abort();
		}
		args->thread[0].pktout = ifs[0].pktout[0];
		args->thread[0].pool = pool;
		args->thread[0].tp = tp;
		args->thread[0].tq = tq;
		args->thread[0].tim = odp_timer_alloc(tp, tq, NULL);
		if (args->thread[0].tim == ODP_TIMER_INVALID) {
			EXAMPLE_ERR("timer_alloc failed\n");
			abort();
		}
		args->thread[0].tmo_ev = odp_timeout_alloc(tmop);
		if (args->thread[0].tmo_ev == ODP_TIMEOUT_INVALID) {
			EXAMPLE_ERR("timeout_alloc failed\n");
			abort();
		}
		args->thread[0].mode = args->appl.mode;
		cpu_next = odp_cpumask_next(&cpumask, cpu_first);
		odp_cpumask_zero(&cpu_mask);
		odp_cpumask_set(&cpu_mask, cpu_next);

		thr_params.start = gen_send_thread;
		thr_params.arg   = &args->thread[0];

		odph_odpthreads_create(&thread_tbl[0], &cpu_mask, &thr_params);

	} else {
		int cpu = odp_cpumask_first(&cpumask);

		for (i = 0; i < num_workers; ++i) {
			odp_cpumask_t thd_mask;
			int (*thr_run_func)(void *);
			int if_idx, pktout_idx;

			if (args->appl.mode == APPL_MODE_RCV)
				(void)args->thread[i].pktout; /*not used*/
			else {
				if_idx = i % args->appl.if_count;
				pktout_idx = (i / args->appl.if_count) %
					ifs[if_idx].pktout_count;

				args->thread[i].pktout =
					ifs[if_idx].pktout[pktout_idx];
			}
			tq = odp_queue_create("", NULL);
			if (tq == ODP_QUEUE_INVALID) {
				EXAMPLE_ERR("queue_create failed\n");
				abort();
			}
			args->thread[i].pool = pool;
			args->thread[i].tp = tp;
			args->thread[i].tq = tq;
			args->thread[i].tim = odp_timer_alloc(tp, tq, NULL);
			if (args->thread[i].tim == ODP_TIMER_INVALID) {
				EXAMPLE_ERR("timer_alloc failed\n");
				abort();
			}
			args->thread[i].tmo_ev = odp_timeout_alloc(tmop);
			if (args->thread[i].tmo_ev == ODP_TIMEOUT_INVALID) {
				EXAMPLE_ERR("timeout_alloc failed\n");
				abort();
			}
			args->thread[i].mode = args->appl.mode;

			if (args->appl.mode == APPL_MODE_UDP) {
				thr_run_func = gen_send_thread;
			} else if (args->appl.mode == APPL_MODE_RCV) {
				thr_run_func = gen_recv_thread;
			} else {
				EXAMPLE_ERR("ERR MODE\n");
				exit(EXIT_FAILURE);
			}
			/*
			 * Create threads one-by-one instead of all-at-once,
			 * because each thread might get different arguments.
			 * Calls odp_thread_create(cpu) for each thread
			 */
			odp_cpumask_zero(&thd_mask);
			odp_cpumask_set(&thd_mask, cpu);

			thr_params.start = thr_run_func;
			thr_params.arg   = &args->thread[i];

			odph_odpthreads_create(&thread_tbl[i],
					       &thd_mask, &thr_params);
			cpu = odp_cpumask_next(&cpumask, cpu);

		}
	}

	print_global_stats(num_workers);

	/* Master thread waits for other threads to exit */
	for (i = 0; i < num_workers; ++i)
		odph_odpthreads_join(&thread_tbl[i]);

	for (i = 0; i < args->appl.if_count; ++i)
		odp_pktio_stop(ifs[i].pktio);

	for (i = 0; i < num_workers; ++i) {
		odp_timer_cancel(args->thread[i].tim, &ev);
		odp_timer_free(args->thread[i].tim);
		odp_timeout_free(args->thread[i].tmo_ev);
	}

	for (i = 0; i < num_workers; ++i) {
		while (1) {
			ev = odp_queue_deq(args->thread[i].tq);
			if (ev == ODP_EVENT_INVALID)
				break;
			odp_event_free(ev);
		}
		odp_queue_destroy(args->thread[i].tq);
	}

	for (i = 0; i < args->appl.if_count; ++i)
		odp_pktio_close(ifs[i].pktio);
	free(ifs);
	free(args->appl.if_names);
	free(args->appl.if_str);
	if (0 != odp_pool_destroy(pool))
		fprintf(stderr, "unable to destroy pool \"pool\"\n");
	odp_timer_pool_destroy(tp);
	if (0 != odp_pool_destroy(tmop))
		fprintf(stderr, "unable to destroy pool \"tmop\"\n");
	if (0 != odp_shm_free(shm))
		fprintf(stderr, "unable to free \"shm\"\n");
	odp_term_local();
	odp_term_global(instance);
	printf("Exit\n\n");

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
	odp_cpumask_t cpumask, cpumask_args, cpumask_and;
	int i, num_workers;
	static const struct option longopts[] = {
		{"interface", required_argument, NULL, 'I'},
		{"workers", required_argument, NULL, 'w'},
		{"cpumask", required_argument, NULL, 'c'},
		{"srcmac", required_argument, NULL, 'a'},
		{"dstmac", required_argument, NULL, 'b'},
		{"srcip", required_argument, NULL, 's'},
		{"dstip", required_argument, NULL, 'd'},
		{"srcport", required_argument, NULL, 'e'},
		{"dstport", required_argument, NULL, 'f'},
		{"packetsize", required_argument, NULL, 'p'},
		{"mode", required_argument, NULL, 'm'},
		{"count", required_argument, NULL, 'n'},
		{"timeout", required_argument, NULL, 't'},
		{"interval", required_argument, NULL, 'i'},
		{"help", no_argument, NULL, 'h'},
		{"udp_tx_burst", required_argument, NULL, 'x'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+I:a:b:s:d:p:i:m:n:t:w:c:x:he:f:";

	/* let helper collect its own arguments (e.g. --odph_proc) */
	odph_parse_options(argc, argv, shortopts, longopts);

	appl_args->mode = -1; /* Invalid, must be changed by parsing */
	appl_args->number = -1;
	appl_args->payload = 56;
	appl_args->timeout = -1;
	appl_args->interval = DEFAULT_PKT_INTERVAL;
	appl_args->udp_tx_burst = 16;
	appl_args->srcport = 0;
	appl_args->dstport = 0;

	opterr = 0; /* do not issue errors on helper options */

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);
		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'w':
			appl_args->num_workers = atoi(optarg);
			break;
		case 'c':
			appl_args->mask = optarg;
			odp_cpumask_from_str(&cpumask_args, args->appl.mask);
			num_workers = odp_cpumask_default_worker(&cpumask, 0);
			odp_cpumask_and(&cpumask_and, &cpumask_args, &cpumask);
			if (odp_cpumask_count(&cpumask_and) <
			    odp_cpumask_count(&cpumask_args)) {
				EXAMPLE_ERR("Wrong cpu mask, max cpu's:%d\n",
					    num_workers);
				exit(EXIT_FAILURE);
			}
			break;
		/* parse packet-io interface names */
		case 'I':
			len = strlen(optarg);
			if (len == 0) {
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

			if (appl_args->if_count == 0) {
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
			if (optarg[0] == 'u') {
				appl_args->mode = APPL_MODE_UDP;
			} else if (optarg[0] == 'p') {
				appl_args->mode = APPL_MODE_PING;
			} else if (optarg[0] == 'r') {
				appl_args->mode = APPL_MODE_RCV;
			} else {
				EXAMPLE_ERR("wrong mode!\n");
				exit(EXIT_FAILURE);
			}
			break;

		case 'a':
			if (odph_eth_addr_parse(&appl_args->srcmac, optarg)) {
				EXAMPLE_ERR("wrong src mac:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'b':
			if (odph_eth_addr_parse(&appl_args->dstmac, optarg)) {
				EXAMPLE_ERR("wrong dst mac:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 's':
			if (scan_ip(optarg, &appl_args->srcip) != 1) {
				EXAMPLE_ERR("wrong src ip:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'd':
			if (scan_ip(optarg, &appl_args->dstip) != 1) {
				EXAMPLE_ERR("wrong dst ip:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'e':
			appl_args->srcport = (unsigned short)atoi(optarg);
			break;
		case 'f':
			appl_args->dstport = (unsigned short)atoi(optarg);
			break;
		case 'p':
			appl_args->payload = atoi(optarg);
			break;

		case 'n':
			appl_args->number = atoi(optarg);
			break;

		case 't':
			appl_args->timeout = atoi(optarg);
			break;

		case 'i':
			appl_args->interval = atoi(optarg);
			if (appl_args->interval <= 200 && geteuid() != 0) {
				EXAMPLE_ERR("should be root user\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'x':
			appl_args->udp_tx_burst = atoi(optarg);
			if (appl_args->udp_tx_burst >  MAX_UDP_TX_BURST) {
				EXAMPLE_ERR("wrong UDP Tx burst size (max %d)\n",
					    MAX_UDP_TX_BURST);
				exit(EXIT_FAILURE);
			}
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}

	if (appl_args->if_count == 0 || appl_args->mode == -1) {
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
	printf("\n"
	       "Mode:            ");
	if (appl_args->mode == 0)
		PRINT_APPL_MODE(APPL_MODE_UDP);
	else if (appl_args->mode == 1)
		PRINT_APPL_MODE(APPL_MODE_PING);
	else
		PRINT_APPL_MODE(APPL_MODE_RCV);
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
	       "  E.g. %s -I eth1 -r\n"
	       "\n"
	       "OpenDataPlane example application.\n"
	       "\n"
	       "  Work mode:\n"
	       "    1.send udp packets\n"
	       "      odp_generator -I eth0 --srcmac fe:0f:97:c9:e0:44  --dstmac 32:cb:9b:27:2f:1a --srcip 192.168.0.1 --dstip 192.168.0.2 -m u\n"
	       "    2.receive udp packets\n"
	       "      odp_generator -I eth0 -m r\n"
	       "    3.work likes ping\n"
	       "      odp_generator -I eth0 --srcmac fe:0f:97:c9:e0:44  --dstmac 32:cb:9b:27:2f:1a --srcip 192.168.0.1 --dstip 192.168.0.2 --cpumask 0xc -m p\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -I, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "  -a, --srcmac src mac address\n"
	       "  -b, --dstmac dst mac address\n"
	       "  -s, --srcip src ip address\n"
	       "  -d, --dstip dst ip address\n"
	       "  -m, --mode work mode: send udp(u), receive(r), send icmp(p)\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -h, --help       Display help and exit.\n"
	       "  -e, --srcport src udp port\n"
	       "  -f, --dstport dst udp port\n"
	       "  -p, --packetsize payload length of the packets\n"
	       "  -t, --timeout only for ping mode, wait ICMP reply timeout seconds\n"
	       "  -i, --interval wait interval ms between sending each packet\n"
	       "                 default is 1000ms. 0 for flood mode\n"
	       "  -w, --workers specify number of workers need to be assigned to application\n"
	       "	         default is to assign all\n"
	       "  -n, --count the number of packets to be send\n"
	       "  -c, --cpumask to set on cores\n"
	       "  -x, --udp_tx_burst size of UDP TX burst\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	      );
}
