/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>

#include <test_debug.h>

#include <odp_debug_internal.h>
#include <odp_api.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>
#include <odp/helper/tcp.h>

#include "odp_l3fwd_db_mv.h"
#include "odp_l3fwd_lpm_mv.h"
#include "ezxml.h"


#define POOL_NUM_PKT	1536 /* 8192 */
#define POOL_SEG_LEN	1856
#define MAX_PKT_BURST	64

#define MAX_NB_WORKER	4
#define MAX_NB_PKTIO	4
#define MAX_NB_QUEUE	32
#define MAX_NB_QCONFS	1024
#define MAX_NB_ROUTE	32

#define INVALID_ID	(-1)
#define PRINT_INTERVAL	1	/* interval seconds of printing stats */
#define PREFETCH_SHIFT	3

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))


struct l3fwd_pktio_s {
	odp_pktio_t pktio;
	odph_ethaddr_t mac_addr;
	odp_pktin_queue_t ifin[MAX_NB_QUEUE];
	odp_pktout_queue_t ifout[MAX_NB_QUEUE];
	int nb_rxq;	/* capa max */
	int nb_txq;	/* capa max */
	int rxq_idx;	/* requested, maybe greater than nb_rxq */
	int txq_idx;	/* requested, maybe greater than nb_txq */
};

struct l3fwd_qconf_s {
	uint8_t if_idx;		/* port index */
	uint8_t rxq_idx;	/* recv queue index in a port */
	uint8_t core_idx;	/* this core should handle traffic */
};

struct thread_arg_s {
	uint64_t packets;
	uint64_t rx_drops;
	uint64_t tx_drops;
	struct {
		int if_idx;	/* interface index */
		int nb_rxq;	/* number of rxq this thread will access */
		int rxq[MAX_NB_QUEUE];	/* rxq[i] is index in pktio.ifin[] */
		int txq_idx;	/* index in pktio.ifout[] */
	} pktio[MAX_NB_PKTIO];
	int nb_pktio;
	int thr_idx;
};

typedef struct {
	char *if_names[MAX_NB_PKTIO];
	int if_count;
	char *route_str[MAX_NB_ROUTE];
	int worker_count;
	struct l3fwd_qconf_s qconf_config[MAX_NB_QCONFS];
	int qconf_count;
	uint32_t duration; /* seconds to run */
	uint8_t hash_mode; /* 1:hash, 0:lpm */
	uint8_t dest_mac_changed[MAX_NB_PKTIO]; /* 1: dest mac from cmdline */
	int error_check; /* Check packets for errors */
} app_args_t;

struct {
	app_args_t		cmd_args;
	struct l3fwd_pktio_s	l3fwd_pktios[MAX_NB_PKTIO];
	odph_odpthread_t	l3fwd_workers[MAX_NB_WORKER];
	struct thread_arg_s	worker_args[MAX_NB_WORKER];
	odph_ethaddr_t		eth_dest_mac[MAX_NB_PKTIO];

	/* forward func, hash or lpm */
	int (*fwd_func)(odp_packet_t pkt, int sif);
} global;

typedef struct {
	char if_name[OIF_LEN];
	odph_ethaddr_t nexthop_mac_addr;
} if_mac_t;

/** Global barrier to synchronize main and workers */
static odp_barrier_t barrier;
static int exit_threads;	/**< Break workers loop if set to 1 */
static int glb_stop;

static int create_pktio(const char *name, odp_pool_t pool,
			struct l3fwd_pktio_s *fwd_pktio)
{
	odp_pktio_param_t pktio_param;
	odp_pktio_config_t config;
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	int rc;

	odp_pktio_param_init(&pktio_param);

	pktio = odp_pktio_open(name, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		printf("Failed to open %s\n", name);
		return -1;
	}
	fwd_pktio->pktio = pktio;

	rc = odp_pktio_capability(pktio, &capa);
	if (rc) {
		printf("Error: pktio %s: unable to read capabilities!\n",
		       name);

		return -1;
	}

	fwd_pktio->nb_rxq = (int)capa.max_input_queues;
	fwd_pktio->nb_txq = (int)capa.max_output_queues;

	if (fwd_pktio->nb_rxq > MAX_NB_QUEUE)
		fwd_pktio->nb_rxq = MAX_NB_QUEUE;

	if (fwd_pktio->nb_txq > MAX_NB_QUEUE)
		fwd_pktio->nb_txq = MAX_NB_QUEUE;

	odp_pktio_config_init(&config);
	/* Checksum Validation */
	config.pktin.bit.ipv4_chksum = 1;
	config.pktin.bit.udp_chksum = 1;
	config.pktin.bit.tcp_chksum = 1;
	/* Checksum  Generation*/
	config.pktout.bit.ipv4_chksum = 0;
	config.pktout.bit.udp_chksum = 0;
	config.pktout.bit.tcp_chksum = 0;
	/* Rx dropping on errors */
	config.pktin.bit.drop_ipv4_err = 0;
	config.pktin.bit.drop_udp_err = 0;
	config.pktin.bit.drop_tcp_err = 0;
	odp_pktio_config(pktio, &config);

	return 0;
}

static void setup_fwd_db(void)
{
	fwd_db_entry_t *entry;
	int if_idx;
	app_args_t *args;

	args = &global.cmd_args;
	if (args->hash_mode)
		init_fwd_hash_cache();
	else
		fib_tbl_init();

	for (entry = fwd_db->list; NULL != entry; entry = entry->next) {
		if_idx = entry->oif_id;
#ifdef _DST_IP_FRWD_
		/*LPM mode*/
		if (!args->hash_mode)
			fib_tbl_insert(entry->subnet.addr, if_idx,
				       entry->subnet.depth);
#endif
		if (args->dest_mac_changed[if_idx])
			global.eth_dest_mac[if_idx] = entry->dst_mac;
		else
			entry->dst_mac = global.eth_dest_mac[if_idx];
	}
}

/**
 * Decrement TTL and incrementally update checksum
 *
 * @param ip  IPv4 header
 */
static inline void ipv4_dec_ttl_csum_update(odph_ipv4hdr_t *ip)
{
	uint16_t a = ~odp_cpu_to_be_16(1 << 8);

	ip->ttl--;
	if (ip->chksum >= a)
		ip->chksum -= a;
	else
		ip->chksum += odp_cpu_to_be_16(1 << 8);
}

static inline int l3fwd_pkt_hash(odp_packet_t pkt, int sif)
{
	fwd_db_entry_t *entry;
	tuple5_t key;
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	int dif;
#ifndef _DST_IP_FRWD_
	odph_udphdr_t  *udp;
#endif
#ifdef _IPV6_ENABLED_
	odph_ipv6hdr_t *ip6;
#endif

	memset(&key, 0, sizeof(tuple5_t));
	ip = odp_packet_l3_ptr(pkt, NULL);
#ifdef _IPV6_ENABLED_
	if (odp_likely(ODPH_IPV4HDR_VER(ip->ver_ihl) == ODPH_IPV4)) {
#endif
		key.u5t.ipv4_5t.dst_ip = odp_be_to_cpu_32(ip->dst_addr);
		if (odp_unlikely((ip->ttl <= 1) ||
			!((ip->proto == ODPH_IPPROTO_UDP) || (ip->proto == ODPH_IPPROTO_TCP)))) {
			/* drop zero TTL or not TCP/UDP traffic */
			odp_packet_free(pkt);
			return INVALID_ID;
		}

#ifndef _DST_IP_FRWD_
		key.ip_protocol = ODPH_IPV4;
		key.u5t.ipv4_5t.src_ip = odp_be_to_cpu_32(ip->src_addr);
		key.u5t.ipv4_5t.proto = ip->proto;
		udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
		key.u5t.ipv4_5t.src_port = odp_be_to_cpu_16(udp->src_port);
		key.u5t.ipv4_5t.dst_port = odp_be_to_cpu_16(udp->dst_port);
#endif

		entry = find_fwd_db_entry(&key);
		if (odp_likely(entry != NULL)) {
			ipv4_dec_ttl_csum_update(ip);
		}
#ifdef _IPV6_ENABLED_
	} else {
		ip6 = odp_packet_l3_ptr(pkt, NULL);
		key.ip_protocol = ODPH_IPV6;
		if (odp_unlikely((ip6->hop_limit <= 1) ||
			!((ip6->next_hdr == ODPH_IPPROTO_UDP) || (ip6->next_hdr == ODPH_IPPROTO_TCP)))) {
			/* drop zero TTL or not TCP/UDP traffic */
			odp_packet_free(pkt);
			return INVALID_ID;
		}

		key.u5t.ipv6_5t.proto = ip6->next_hdr;
		memcpy(&key.u5t.ipv6_5t.dst_ipv6, ip6->dst_addr, ODPH_IPV6ADDR_LEN);
		memcpy(&key.u5t.ipv6_5t.src_ipv6, ip6->src_addr, ODPH_IPV6ADDR_LEN);
		udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
		key.u5t.ipv6_5t.src_port = odp_be_to_cpu_16(udp->src_port);
		key.u5t.ipv6_5t.dst_port = odp_be_to_cpu_16(udp->dst_port);

		entry = find_fwd_db_entry(&key);
		if (odp_likely(entry != NULL)) {
			ip6->hop_limit--;
		}
	}
#endif

	if (odp_likely(entry != NULL)) {
		eth = odp_packet_l2_ptr(pkt, NULL);
		eth->src = entry->src_mac;
		eth->dst = entry->dst_mac;
		dif = entry->oif_id;
	} else {
		dif = sif; /* TBD remove sif and remove this line */

		/* no route, drop */
		odp_packet_free(pkt);
		return INVALID_ID;
	}

	return dif;
}

static inline int l3fwd_pkt_lpm(odp_packet_t pkt, int sif)
{
	odph_ipv4hdr_t *ip;
	odph_ethhdr_t *eth;
	int dif;
	int ret;

	ip = odp_packet_l3_ptr(pkt, NULL);
	ipv4_dec_ttl_csum_update(ip);
	eth = odp_packet_l2_ptr(pkt, NULL);

	/* network byte order maybe different from host */
	ret = fib_tbl_lookup(odp_be_to_cpu_32(ip->dst_addr), &dif);
	if (ret)
		dif = sif;

	eth->dst = global.eth_dest_mac[dif];
	eth->src = global.l3fwd_pktios[dif].mac_addr;

	return dif;
}

/**
 * Drop unsupported packets and packets containing errors.
 *
 * Frees packets with errors or unsupported protocol and modifies pkt_tbl[] to
 * only contain valid packets.
 *
 * @param pkt_tbl  Array of packets
 * @param num      Number of packets in pkt_tbl[]
 *
 * @return Number of packets dropped
 */
static inline int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned num)
{
	odp_packet_t pkt;
	unsigned dropped = 0;
	unsigned i, j;
	int err;

	for (i = 0, j = 0; i < num; ++i) {
		pkt = pkt_tbl[i];
		err = 0;

		if (global.cmd_args.error_check)
			err = odp_packet_has_error(pkt);

		if (odp_unlikely(err || !(odp_packet_has_ipv4(pkt) ||
								odp_packet_has_ipv6(pkt)))) {
			odp_packet_free(pkt);
			dropped++;
		} else if (odp_unlikely(i != j++)) {
			pkt_tbl[j - 1] = pkt;
		}
	}

	return dropped;
}

static int run_worker(void *arg)
{
	int if_idx;
	struct thread_arg_s *thr_arg = arg;
	odp_pktin_queue_t inq;
	int input_ifs[thr_arg->nb_pktio];
	odp_pktin_queue_t input_queues[thr_arg->nb_pktio];
	odp_pktout_queue_t output_queues[global.cmd_args.if_count];
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	odp_packet_t *tbl;
	int pkts, drop, sent;
	int dst_port, dif;
	int i, j;
	int pktio = 0;
	int num_pktio = 0;

	/* Copy all required handles to local memory */
	for (i = 0; i < global.cmd_args.if_count; i++) {
		int txq_idx = thr_arg->pktio[i].txq_idx;

		output_queues[i] =  global.l3fwd_pktios[i].ifout[txq_idx];

		if_idx = thr_arg->pktio[i].if_idx;
		for (j = 0; j < thr_arg->pktio[i].nb_rxq; j++) {
			int rxq_idx = thr_arg->pktio[i].rxq[j];

			inq = global.l3fwd_pktios[if_idx].ifin[rxq_idx];
			input_ifs[num_pktio] = if_idx;
			input_queues[num_pktio] = inq;
			num_pktio++;
		}
	}

	if (num_pktio == 0)
		LOG_ABORT("No pktio devices found\n");

	if_idx = input_ifs[pktio];
	inq = input_queues[pktio];

	odp_barrier_wait(&barrier);

	while (!exit_threads) {
		if (num_pktio > 1) {
			if_idx = input_ifs[pktio];
			inq = input_queues[pktio];
			pktio++;
			if (pktio == num_pktio)
				pktio = 0;
		}

		pkts = odp_pktin_recv(inq, pkt_tbl, MAX_PKT_BURST);
		if (pkts < 1)
			continue;

		thr_arg->packets += pkts;
		drop = drop_err_pkts(pkt_tbl, pkts);
		pkts -= drop;
		thr_arg->rx_drops += drop;
		if (odp_unlikely(pkts < 1))
			continue;

		/* find dest interface for the first packet in the queue */
		dif = global.fwd_func(pkt_tbl[0], if_idx);
		tbl = &pkt_tbl[0];
		while (pkts > 0) {
			/* advance until the packets are forwarded to the same if and
			   send them at once */
			dst_port = dif;
			for (i = 1; i < pkts; i++) {
				if (pkts-i > PREFETCH_SHIFT)
					odp_packet_prefetch(tbl[i+PREFETCH_SHIFT], 0, 64);
				dif = global.fwd_func(tbl[i], if_idx);
				if (odp_unlikely(dif != dst_port))
					break;
			}

			/* FWD rule dropped the packets, update counters */
			if (odp_unlikely(dst_port == INVALID_ID)) {
				thr_arg->rx_drops += i;
			}
			else {
				sent = odp_pktout_send(output_queues[dst_port], tbl, i);
				if (odp_unlikely(sent < i)) {
					sent = sent < 0 ? 0 : sent;
					odp_packet_free_multi(&tbl[sent], i - sent);
					thr_arg->tx_drops += i - sent;
				}
			}

			if (i < pkts)
				tbl += i;

			pkts -= i;
		}
	}

	/* Make sure that latest stat writes are visible to other threads */
	odp_mb_full();

	return 0;
}

static int find_port_id_by_name(char *name, app_args_t *args)
{
	int i;

	if (!name)
		return -1;

	for (i = 0; i < args->if_count; i++) {
		if (!strcmp(name, args->if_names[i]))
			return i;
	}

	return -1;
}

/* split string into tokens */
static int split_string(char *str, int stringlen,
			char **tokens, int maxtokens, char delim)
{
	int i, tok = 0;
	int tokstart = 1; /* first token is right at start of string */

	if (str == NULL || tokens == NULL)
		goto einval_error;

	for (i = 0; i < stringlen; i++) {
		if (str[i] == '\0' || tok >= maxtokens)
			break;
		if (tokstart) {
			tokstart = 0;
			tokens[tok++] = &str[i];
		}
		if (str[i] == delim) {
			str[i] = '\0';
			tokstart = 1;
		}
	}
	return tok;

einval_error:
	errno = EINVAL;
	return -1;
}

static int parse_config(char *cfg_str, app_args_t *args)
{
	char s[256];
	const char *p, *p0 = cfg_str;
	char *end;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_QUEUE,
		FLD_LCORE,
		FLD_LAST
	};
	unsigned long int_fld[FLD_LAST];
	char *str_fld[FLD_LAST];
	int i;
	unsigned size;
	int nb_qconfs = 0;
	struct l3fwd_qconf_s *qconf_array = &args->qconf_config[0];

	p = strchr(p0, '(');
	while (p != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		i = split_string(s, sizeof(s), str_fld, FLD_LAST, ',');
		if (i != FLD_LAST)
			return -1;
		for (i = 0; i < FLD_LAST; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
				return -1;
		}
		if (nb_qconfs >= MAX_NB_QCONFS) {
			printf("exceeded max number of queue params: %d\n",
			       nb_qconfs);
			return -1;
		}
		qconf_array[nb_qconfs].if_idx = (uint8_t)int_fld[FLD_PORT];
		qconf_array[nb_qconfs].rxq_idx = (uint8_t)int_fld[FLD_QUEUE];
		qconf_array[nb_qconfs].core_idx = (uint8_t)int_fld[FLD_LCORE];
		++nb_qconfs;

		p = strchr(p0, '(');
	}
	args->qconf_count = nb_qconfs;

	return 0;
}

static void print_usage(char *progname)
{
#ifdef _DST_IP_FRWD_
	printf("\n"
	       "ODP L3 forwarding application.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth0,eth1 -r 1.1.1.0/24,eth0 -r 2.2.2.0/24,eth1\n"
	       " In the above example,\n"
	       " eth0 will send pkts to eth1 and vice versa\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface eth interfaces (comma-separated, no spaces)\n"
	       "  -r, --route SubNet,Intf[,NextHopMAC]\n"
	       "	NextHopMAC can be optional\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -s, --style [lpm|hash], ip lookup method\n"
	       "	optional, default as lpm\n"
	       "  -d, --duration Seconds to run and print stats\n"
	       "	optional, default as 0, run forever\n"
	       "  -t, --thread Number of threads to do forwarding\n"
	       "	optional, default as availbe worker cpu count\n"
	       "  -q, --queue  Configure rx queue(s) for port\n"
	       "	optional, format: [(port, queue, thread),...]\n"
	       "	for example: -q '(0, 0, 1),(1,0,2)'\n"
	       "  -e, --error_check 0: Don't check packet errors (default)\n"
	       "                    1: Check packet errors\n"
	       "  -h, --help   Display help and exit.\n\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
#else
	printf("\n"
	       "ODP L3 forwarding application.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth0,eth1 -r 1.1.1.0/24,2.2.2.0/24,2002,2003,0,eth1\n"
	       " In the above example,\n"
	       " eth0 will send pkts to eth1\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface eth interfaces (comma-separated, no spaces)\n"
	       "  -r, --route Src_SubNet,Dst_SubNet,Src_Port,Dst_Port,0-UDP/1-TCP,Dst_Intf[,NextHopMAC]\n"
	       "	NextHopMAC can be optional\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -d, --duration Seconds to run and print stats\n"
	       "	optional, default as 0, run forever\n"
	       "  -t, --thread Number of threads to do forwarding\n"
	       "	optional, default as availbe worker cpu count\n"
	       "  -q, --queue  Configure rx queue(s) for port\n"
	       "	optional, format: [(port, queue, thread),...]\n"
	       "	for example: -q '(0, 0, 1),(1,0,2)'\n"
	       "  -e, --error_check 0: Don't check packet errors (default)\n"
	       "                    1: Check packet errors\n"
	       "  -h, --help   Display help and exit.\n\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
#endif
}

static void parse_cmdline_args(int argc, char *argv[], app_args_t *args)
{
	int opt;
	int long_index;
	char *token, *local;
	size_t len, route_index = 0;
	int i, mem_failure = 0;

	static struct option longopts[] = {
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"route", required_argument, NULL, 'r'},	/* return 'r' */
		{"style", optional_argument, NULL, 's'},	/* return 's' */
		{"duration", optional_argument, NULL, 'd'},	/* return 'd' */
		{"thread", optional_argument, NULL, 't'},	/* return 't' */
		{"queue", optional_argument, NULL, 'q'},	/* return 'q' */
		{"error_check", optional_argument, NULL, 'e'},
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	while (1) {
#ifdef _DST_IP_FRWD_
		opt = getopt_long(argc, argv, "+s:t:d:i:r:q:e:h",
				  longopts, &long_index);
#else
		opt = getopt_long(argc, argv, "+t:d:i:r:q:e:h",
				  longopts, &long_index);
#endif
		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
#ifdef _DST_IP_FRWD_
		/* parse ip lookup method */
		case 's':
			if (!strcmp(optarg, "hash"))
				args->hash_mode = 1;
			break;
#endif
		/* parse number of worker threads to be run*/
		case 't':
			i = odp_cpu_count();
			args->worker_count = atoi(optarg);
			if (args->worker_count > i) {
				printf("Too many threads,"
				       "truncate to cpu count: %d\n", i);
				args->worker_count = i;
			}

			break;

		/* parse seconds to run */
		case 'd':
			args->duration = atoi(optarg);
			break;

		/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			local = malloc(len);
			if (!local) {
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(local, optarg);
			for (token = strtok(local, ","), i = 0;
			     token != NULL;
			     token = strtok(NULL, ","), i++)
				;

			if (i == 0) {
				print_usage(argv[0]);
				free(local);
				exit(EXIT_FAILURE);
			} else if (i > MAX_NB_PKTIO) {
				printf("too many ports specified, "
				       "truncated to %d", MAX_NB_PKTIO);
			}
			args->if_count = i;

			/* store the if names (reset names string) */
			strcpy(local, optarg);
			for (token = strtok(local, ","), i = 0;
			     token != NULL; token = strtok(NULL, ","), i++) {
				args->if_names[i] = token;
			}
			break;

		/*Configure Route in forwarding database*/
		case 'r':
			if (route_index >= MAX_NB_ROUTE) {
				printf("No more routes can be added\n");
				break;
			}
			local = calloc(1, strlen(optarg) + 1);
			if (!local) {
				mem_failure = 1;
				break;
			}
			memcpy(local, optarg, strlen(optarg));
			local[strlen(optarg)] = '\0';
			args->route_str[route_index++] = local;
			break;

		case 'e':
			args->error_check = atoi(optarg);
			break;

		case 'h':
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		case 'q':
			parse_config(optarg, args);
			break;

		default:
			break;
		}
	}

#ifndef _DST_IP_FRWD_
	args->hash_mode = 1;
#endif

	/* checking arguments */
	if (args->if_count == 0) {
		printf("\nNo option -i specified.\n");
		goto out;
	}

	if (args->route_str[0] == NULL) {
		printf("\nNo option -r specified.\n");
		goto out;
	}

	if (mem_failure == 1) {
		printf("\nAllocate memory failure.\n");
		goto out;
	}
	optind = 1;		/* reset 'extern optind' from the getopt lib */
	return;

out:
	print_usage(argv[0]);
	exit(EXIT_FAILURE);
}

static void print_info(char *progname, app_args_t *args)
{
	int i;

	printf("\n"
	       "ODP system info\n"
	       "---------------\n"
	       "ODP API version: %s\n"
	       "ODP impl name:	 %s\n"
	       "CPU model:       %s\n"
	       "CPU freq (hz):   %" PRIu64 "\n"
	       "Cache line size: %i\n"
	       "CPU count:       %i\n"
	       "\n",
	       odp_version_api_str(), odp_version_impl_name(),
	       odp_cpu_model_str(), odp_cpu_hz_max(),
	       odp_sys_cache_line_size(), odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "IP Lookup:	 %s\n"
	       "IF Count:        %i\n"
	       "Using IFs:      ",
	       progname,
	       args->hash_mode ? "hash" : "lpm",
	       args->if_count);

	for (i = 0; i < args->if_count; ++i)
		printf(" %s", args->if_names[i]);

	printf("\n\n");
	fflush(NULL);
}

#ifndef _DST_IP_FRWD_
static void init_mac_table(if_mac_t *if_mac_table, app_args_t *args) {
	ezxml_t nhop;
	int i, j;

	ezxml_t mac_xml = ezxml_parse_file("IfToMac.xml");
	if (mac_xml == NULL) {
		return;
	}

	printf("Parsing next hop table xml\n");
	i = 0;
	for (nhop = ezxml_child(mac_xml, "Nexthop"); nhop && (++i < MAX_NB_PKTIO); nhop = nhop->next) {
		if (ezxml_child(nhop, "If") && ezxml_child(nhop, "Mac")) {
			strcpy(if_mac_table[i].if_name, ezxml_child(nhop, "If")->txt);
			if (odph_eth_addr_parse(&if_mac_table[i].nexthop_mac_addr, ezxml_child(nhop, "Mac")->txt) != 0) {
				printf("init_mac_table: invalid nexthop MAC address\n");
				exit(EXIT_FAILURE);
			}
		}
	}
	ezxml_free(mac_xml);

	for (i = 0; i < MAX_NB_PKTIO; i++) {
		for (j = 0; j < MAX_NB_PKTIO; j++) {
			if (args->if_names[i]) {
				if (strcmp(args->if_names[i], if_mac_table[j].if_name) == 0) {
					memcpy(global.eth_dest_mac[i].addr, if_mac_table[j].nexthop_mac_addr.addr, ODPH_ETHADDR_LEN);
					break;
				}
			}
		}
	}
}

static void parse_routing_xml(app_args_t *args) {
	ezxml_t rentry;
	ezxml_t tuple;
	int outif;
	fwd_db_entry_t *entry;
	int i = 0;

	ezxml_t route_xml = ezxml_parse_file("L3Routing.xml");
	if (route_xml == NULL) {
		return;
	}
	printf("Parsing routing xml\n");

	for (rentry = ezxml_child(route_xml, "RouteEntry"); rentry; rentry = rentry->next) {
		if (ezxml_child(rentry, "Tuple") && ezxml_child(rentry, "OutIf")) {
			tuple = ezxml_child(rentry, "Tuple");
			if (!(ezxml_child(tuple, "SrcIP") && ezxml_child(tuple, "DstIP") && ezxml_child(tuple, "SrcPort") &&
				ezxml_child(tuple, "DstPort") && ezxml_child(tuple, "Protocol"))) {
					printf("parse_routing_xml: invalid 5-Tuple\n");
					exit(EXIT_FAILURE);
			}

			if (MAX_DB <= fwd_db->index) {
				printf("parse_routing_xml: out of space\n");
				return;
			}

			entry = &fwd_db->array[fwd_db->index];
			if (entry == NULL) {
				printf("parse_routing_xml: not initialized entry\n");
				exit(EXIT_FAILURE);
			}
			if (parse_ipv4_string(ezxml_child(tuple, "SrcIP")->txt,
					&entry->u.ipv4.src_subnet.addr, &entry->u.ipv4.src_subnet.depth) == -1) {
				if (parse_ipv6_string(ezxml_child(tuple, "SrcIP")->txt,
						&entry->u.ipv6.src_subnet.addr.u64.ipv6_hi,
						&entry->u.ipv6.src_subnet.addr.u64.ipv6_lo,
						&entry->u.ipv6.src_subnet.prefix) == -1) {
					printf("Skipping xml entry: invalid SrcIp\n");
					memset(entry, 0, sizeof(fwd_db_entry_t));
					continue;
				} else {
					entry->ip_protocol = ODPH_IPV6;
				}
			} else {
				entry->ip_protocol = ODPH_IPV4;
			}
			if (entry->ip_protocol == ODPH_IPV4) {
				if (parse_ipv4_string(ezxml_child(tuple, "DstIP")->txt,
						&entry->u.ipv4.dst_subnet.addr, &entry->u.ipv4.dst_subnet.depth) == -1) {
					printf("Skipping xml entry: invalid DstIp\n");
					memset(entry, 0, sizeof(fwd_db_entry_t));
					continue;
				}
			} else {
				if (parse_ipv6_string(ezxml_child(tuple, "DstIP")->txt,
						&entry->u.ipv6.dst_subnet.addr.u64.ipv6_hi,
						&entry->u.ipv6.dst_subnet.addr.u64.ipv6_lo,
						&entry->u.ipv6.dst_subnet.prefix) == -1) {
					printf("Skipping xml entry: invalid DstIp\n");
					memset(entry, 0, sizeof(fwd_db_entry_t));
					continue;
				}
			}
			if (entry->ip_protocol == ODPH_IPV4) {
				entry->u.ipv4.src_port = atoi(ezxml_child(tuple, "SrcPort")->txt);
				entry->u.ipv4.dst_port = atoi(ezxml_child(tuple, "DstPort")->txt);
			} else {
				entry->u.ipv6.src_port = atoi(ezxml_child(tuple, "SrcPort")->txt);
				entry->u.ipv6.dst_port = atoi(ezxml_child(tuple, "DstPort")->txt);
			}
			if (strcmp(ezxml_child(tuple, "Protocol")->txt, "UDP") == 0) {
				if (entry->ip_protocol == ODPH_IPV4) {
					entry->u.ipv4.protocol = ODPH_IPPROTO_UDP;
				} else {
					entry->u.ipv6.protocol = ODPH_IPPROTO_UDP;
				}
			}
			else {
				if (strcmp(ezxml_child(tuple, "Protocol")->txt, "TCP") == 0) {
					if (entry->ip_protocol == ODPH_IPV4) {
						entry->u.ipv4.protocol = ODPH_IPPROTO_TCP;
					} else {
						entry->u.ipv6.protocol = ODPH_IPPROTO_TCP;
					}
				}
				else {
					printf("Skipping xml entry: Invalid protocol %s\n", ezxml_child(tuple, "Protocol")->txt);
					memset(entry, 0, sizeof(fwd_db_entry_t));
					continue;
				}
			}

			strncpy(entry->oif, ezxml_child(rentry, "OutIf")->txt, OIF_LEN - 1);
			entry->oif[OIF_LEN - 1] = 0;
			outif = find_port_id_by_name(entry->oif, args);
			if (outif == -1) {
				printf("Skipping xml entry: port %s is not used.\n", entry->oif);
				memset(entry, 0, sizeof(fwd_db_entry_t));
				continue;
			}

#ifndef _IPV6_ENABLED_
			/* skip IPv6 entries when IPv6 is disabled */
			if (entry->ip_protocol == ODPH_IPV4) {
#endif
			/* Add route to the list */
			fwd_db->index++;
			entry->next = fwd_db->list;
			fwd_db->list = entry;
			++i;
#ifndef _IPV6_ENABLED_
			}
#endif
		}
	}
	ezxml_free(route_xml);
	printf("Routing xml: found %d entries\n", i);
}
#endif

/**
 * Setup rx and tx queues, distribute them among threads.
 *
 * If no q argument, the queues are distribute among threads as default.
 * The thread take one rx queue of a port one time as round-robin order.
 * One txq for each thread on each port
 */
static void setup_worker_qconf(app_args_t *args)
{
	int nb_worker, if_count, pktio;
	int i, j, rxq_idx;
	struct thread_arg_s *arg;
	struct l3fwd_pktio_s *port;
	uint8_t queue_mask[MAX_NB_PKTIO][MAX_NB_QUEUE];

	nb_worker = args->worker_count;
	if_count = args->if_count;

	/* distribute rx queues among threads as round-robin */
	if (!args->qconf_count) {
		if (nb_worker > if_count) {
			for (i = 0; i < nb_worker; i++) {
				arg = &global.worker_args[i];
				arg->thr_idx = i;
				j = i % if_count;
				port = &global.l3fwd_pktios[j];
				arg->pktio[0].rxq[0] =
					port->rxq_idx % port->nb_rxq;
				arg->pktio[0].nb_rxq = 1;
				arg->pktio[0].if_idx = j;
				arg->nb_pktio = 1;
				port->rxq_idx++;
			}
		} else {
			for (i = 0; i < if_count; i++) {
				j = i % nb_worker;
				arg = &global.worker_args[j];
				arg->thr_idx = j;
				port = &global.l3fwd_pktios[i];
				rxq_idx = arg->pktio[i].nb_rxq;
				pktio = arg->nb_pktio;
				arg->pktio[pktio].rxq[rxq_idx] =
					port->rxq_idx % port->nb_rxq;
				arg->pktio[pktio].nb_rxq++;
				arg->pktio[pktio].if_idx = i;
				arg->nb_pktio++;
				port->rxq_idx++;
			}
		}
	}

	/* distribute rx queues among threads as q argument */
	memset(queue_mask, 0, sizeof(queue_mask));
	for (i = 0; i < args->qconf_count; i++) {
		struct l3fwd_qconf_s *q;

		q = &args->qconf_config[i];
		if (q->core_idx >= nb_worker || q->if_idx >= if_count)
			LOG_ABORT("Error queue (%d, %d, %d), max port: "
				  "%d, max core: %d\n", q->if_idx, q->rxq_idx,
				  q->core_idx, args->if_count - 1,
				  args->worker_count - 1);

		/* check if one queue is configured twice or more */
		if (queue_mask[q->if_idx][q->rxq_idx])
			LOG_ABORT("Error queue (%d, %d, %d), reconfig queue\n",
				  q->if_idx, q->rxq_idx, q->core_idx);
		queue_mask[q->if_idx][q->rxq_idx] = 1;

		port = &global.l3fwd_pktios[q->if_idx];
		if (port->rxq_idx < q->rxq_idx)
			LOG_ABORT("Error queue (%d, %d, %d), queue should be"
				  " in sequence and start from 0, queue %d\n",
				  q->if_idx, q->rxq_idx, q->core_idx,
				  q->rxq_idx);

		if (q->rxq_idx > port->nb_rxq) {
			LOG_ABORT("Error queue (%d, %d, %d), max queue %d\n",
				  q->if_idx, q->rxq_idx, q->core_idx,
				  port->nb_rxq - 1);
		}
		port->rxq_idx = q->rxq_idx + 1;

		/* put the queue into worker_args */
		arg = &global.worker_args[q->core_idx];

		/* Check if interface already has queues configured */
		for (j = 0; j < args->if_count; j++) {
			if (arg->pktio[j].if_idx == q->if_idx)
				break;
		}
		if (j == args->if_count)
			j = arg->nb_pktio++;

		rxq_idx =  arg->pktio[j].nb_rxq;
		arg->pktio[j].rxq[rxq_idx] = q->rxq_idx;
		arg->pktio[j].nb_rxq++;
		arg->pktio[j].if_idx = q->if_idx;
		arg->thr_idx = q->core_idx;
	}
	/* distribute tx queues among threads */
	for (i = 0; i < args->worker_count; i++) {
		arg = &global.worker_args[i];
		for (j = 0; j < args->if_count; j++) {
			port = &global.l3fwd_pktios[j];
			arg->pktio[j].txq_idx =
				port->txq_idx % port->nb_txq;
			port->txq_idx++;
		}
	}

	/* config and initialize rx and tx queues. */
	for (i = 0; i < if_count; i++) {
		odp_pktin_queue_param_t in_queue_param;
		odp_pktout_queue_param_t out_queue_param;
		odp_pktin_queue_t *inq;
		odp_pktout_queue_t *outq;
		const char *name;
		int nb_rxq, nb_txq;

		port = &global.l3fwd_pktios[i];
		name = args->if_names[i];
		odp_pktin_queue_param_init(&in_queue_param);
		odp_pktout_queue_param_init(&out_queue_param);

		in_queue_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
		out_queue_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;

		in_queue_param.hash_enable = 1;
		in_queue_param.hash_proto.proto.ipv4 = 0;
		in_queue_param.hash_proto.proto.ipv4_tcp = 1;
		in_queue_param.hash_proto.proto.ipv4_udp = 1;

		in_queue_param.num_queues = port->rxq_idx;
		if (port->rxq_idx > port->nb_rxq) {
			in_queue_param.num_queues = port->nb_rxq;
			in_queue_param.op_mode = ODP_PKTIO_OP_MT;
		}

		if (odp_pktin_queue_config(port->pktio, &in_queue_param))
			LOG_ABORT("Fail to config input queue for port %s\n",
				  name);

		out_queue_param.num_queues = port->txq_idx;
		if (port->txq_idx > port->nb_txq) {
			out_queue_param.num_queues = port->nb_txq;
			out_queue_param.op_mode = ODP_PKTIO_OP_MT;
		}
		if (odp_pktout_queue_config(port->pktio, &out_queue_param))
			LOG_ABORT("Fail to config output queue for port %s\n",
				  name);

		inq = port->ifin;
		nb_rxq = in_queue_param.num_queues;
		if (odp_pktin_queue(port->pktio, inq, nb_rxq) != nb_rxq)
			LOG_ABORT("Fail to set pktin queue for port %s\n",
				  name);

		outq = port->ifout;
		nb_txq = out_queue_param.num_queues;
		if (odp_pktout_queue(port->pktio, outq, nb_txq) != nb_txq)
			LOG_ABORT("Fail to set pktout queue for port %s\n",
				  name);
	}
}

static void print_qconf_table(app_args_t *args)
{
	int i, j, k, qid, if_idx;
	char buf[32];
	char buf2[32];
	struct thread_arg_s *thr_arg;

	printf("Rx Queue table\n"
	       "-----------------\n"
	       "%-32s%-16s%-16s%-32s\n",
	       "port/id", "rxq", "thread", "eth_dest_mac");

	for (i = 0; i < args->worker_count; i++) {
		thr_arg = &global.worker_args[i];
		for (j = 0; j < args->if_count; j++) {
			if (!thr_arg->pktio[j].nb_rxq)
				continue;

			if_idx = thr_arg->pktio[j].if_idx;
			snprintf(buf, 32, "%s/%d", args->if_names[if_idx],
				 if_idx);
			for (k = 0; k < MAX_NB_QUEUE; k++) {
				qid = thr_arg->pktio[j].rxq[k];
				if (qid != INVALID_ID)
					printf("%-32s%-16d%-16d\n", buf, qid,
					       thr_arg->thr_idx);
			}

			sprintf(buf2, "%02x:%02x:%02x:%02x:%02x:%02x",
				global.eth_dest_mac[j].addr[0],
				global.eth_dest_mac[j].addr[1],
				global.eth_dest_mac[j].addr[2],
				global.eth_dest_mac[j].addr[3],
				global.eth_dest_mac[j].addr[4],
				global.eth_dest_mac[j].addr[5]);
			printf("%-32s\n", buf2);
		}
	}
	printf("\n");
	fflush(NULL);
}

/**
 *  Print statistics
 *
 * @param num_workers Number of worker threads
 * @param duration Number of seconds to loop in
 * @param timeout Number of seconds for stats calculation
 *
 */
static int print_speed_stats(int num_workers, int duration, int timeout)
{
	uint64_t pkts = 0;
	uint64_t pkts_prev = 0;
	uint64_t pps;
	uint64_t rx_drops, tx_drops;
	uint64_t maximum_pps = 0;
	int i;
	int elapsed = 0;
	int stats_enabled = 1;
	int loop_forever = (duration == 0);

	if (timeout <= 0) {
		stats_enabled = 0;
		timeout = 1;
	}
	/* Wait for all threads to be ready*/
	odp_barrier_wait(&barrier);

	do {
		pkts = 0;
		rx_drops = 0;
		tx_drops = 0;
		sleep(timeout);

		for (i = 0; i < num_workers; i++) {
			pkts += global.worker_args[i].packets;
			rx_drops += global.worker_args[i].rx_drops;
			tx_drops += global.worker_args[i].tx_drops;
		}
		if (stats_enabled) {
			pps = (pkts - pkts_prev) / timeout;
			if (pps > maximum_pps)
				maximum_pps = pps;
			printf("%" PRIu64 " pps, %" PRIu64 " max pps, ",  pps,
			       maximum_pps);

			printf(" %" PRIu64 " rx drops, %" PRIu64 " tx drops\n",
			       rx_drops, tx_drops);

			pkts_prev = pkts;
		}
		elapsed += timeout;
	} while (!glb_stop && (loop_forever || (elapsed < duration)));

	if (stats_enabled)
		printf("TEST RESULT: %" PRIu64 " maximum packets per second.\n",
		       maximum_pps);

	return pkts > 100 ? 0 : -1;
}

static void sig_int_handler(int sig)
{
	if (sig == SIGINT) {
		glb_stop = 1;
		exit_threads = 1;
	}
}

int main(int argc, char **argv)
{
	odph_odpthread_t thread_tbl[MAX_NB_WORKER];
	odp_pool_t pool;
	odp_pool_param_t params;
	odp_instance_t instance;
	odph_odpthread_params_t thr_params;
	odp_cpumask_t cpumask;
	int cpu, i, j, nb_worker;
	uint8_t mac[ODPH_ETHADDR_LEN];
	uint8_t *dst_mac;
	app_args_t *args;
	struct thread_arg_s *thr_arg;
	char *oif;
	int ret;
	if_mac_t if_mac_table[MAX_NB_PKTIO];
	odp_init_t odp_init_params;
	odp_cpumask_t worker_cpu_mask;
	odp_cpumask_t control_cpu_mask;

	if (signal(SIGINT, sig_int_handler) != 0) {
		printf("Error: register to SIGINT failed\n");
		exit(EXIT_FAILURE);
	}

	memset(&odp_init_params, 0, sizeof(odp_init_params));
	odp_cpumask_zero(&control_cpu_mask);
	odp_cpumask_zero(&worker_cpu_mask);
	odp_cpumask_set(&control_cpu_mask, 0);

	for (i = 0; i < MAX_NB_WORKER; i++)
		odp_cpumask_set(&worker_cpu_mask, i);

	odp_init_params.worker_cpus = &worker_cpu_mask;
	odp_init_params.control_cpus = &control_cpu_mask;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &odp_init_params, NULL)) {
		printf("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		printf("Error: ODP local init failed.\n");
		exit(1);
	}

	/* Clear global argument and initialize the dest mac as 2:0:0:0:0:x */
	memset(&global, 0, sizeof(global));
	memset(mac,0,ODPH_ETHADDR_LEN);
	mac[0] = 2;
	for (i = 0; i < MAX_NB_PKTIO; i++) {
		mac[ODPH_ETHADDR_LEN - 1] = (uint8_t)i;
		memcpy(global.eth_dest_mac[i].addr, mac, ODPH_ETHADDR_LEN);
	}

	/* Initialize the thread arguments */
	for (i = 0; i < MAX_NB_WORKER; i++) {
		thr_arg = &global.worker_args[i];
		for (j = 0; j < MAX_NB_PKTIO; j++) {
			thr_arg->thr_idx = INVALID_ID;
			thr_arg->pktio[j].txq_idx = INVALID_ID;
			thr_arg->pktio[j].if_idx = INVALID_ID;
			memset(thr_arg->pktio[j].rxq, INVALID_ID,
			       sizeof(thr_arg->pktio[j].rxq));
		}
	}

	/* Parse cmdline arguments */
	args = &global.cmd_args;
	parse_cmdline_args(argc, argv, args);

	/* read MACs table file and configure interface MAC addresses */
	memset(if_mac_table, 0, sizeof(if_mac_t) * MAX_NB_PKTIO);

#ifndef _DST_IP_FRWD_
	init_mac_table(if_mac_table, args);
#endif
	/* Init l3fwd table */
	init_fwd_db();

	/* Add route into table */
	for (i = 0; i < MAX_NB_ROUTE; i++) {
		if (args->route_str[i]) {
			if (create_fwd_db_entry(args->route_str[i], &oif, &dst_mac) == -1) {
				printf("Error: fail to create route entry.\n");
				exit(1);
			}

			if (oif == NULL) {
				printf("Error: fail to create route entry.\n");
				exit(1);
			}

			j = find_port_id_by_name(oif, args);
			if (j == -1) {
				printf("Error: port %s not used.\n", oif);
				exit(1);
			}

			if (dst_mac)
				args->dest_mac_changed[j] = 1;
		}
	}

#ifndef _DST_IP_FRWD_
	/* routing xml entries are added to the fw db after command line configuration */
	parse_routing_xml(args);
#endif

	print_info(NO_PATH(argv[0]), args);

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = POOL_SEG_LEN;
	params.pkt.len     = POOL_SEG_LEN;
	params.pkt.num     = POOL_NUM_PKT;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet pool", &params);

	if (pool == ODP_POOL_INVALID) {
		printf("Error: packet pool create failed.\n");
		exit(1);
	}

	/* Resolve fwd db*/
	for (i = 0; i < args->if_count; i++) {
		struct l3fwd_pktio_s *port;
		char *if_name;

		if_name = args->if_names[i];
		port = &global.l3fwd_pktios[i];
		if (create_pktio(if_name, pool, port)) {
			printf("Error: create pktio %s\n", if_name);
			exit(1);
		}
		odp_pktio_mac_addr(port->pktio, mac, ODPH_ETHADDR_LEN);
		resolve_fwd_db(if_name, i, mac);
		memcpy(port->mac_addr.addr, mac, ODPH_ETHADDR_LEN);
	}
	setup_fwd_db();
	dump_fwd_db();

	/* Dicide available workers */
	nb_worker = MAX_NB_WORKER;
	if (args->worker_count)
		nb_worker = args->worker_count;

	nb_worker = odp_cpumask_default_worker(&cpumask, nb_worker);
	args->worker_count = nb_worker;

	/* Setup rx and tx queues for each port */
	setup_worker_qconf(args);
	print_qconf_table(args);

	/* Decide ip lookup method */
	if (args->hash_mode)
		global.fwd_func = l3fwd_pkt_hash;
	else
		global.fwd_func = l3fwd_pkt_lpm;

	/* Start all the available ports */
	for (i = 0; i < args->if_count; i++) {
		struct l3fwd_pktio_s *port;
		char *if_name;
		char buf[32];

		if_name = args->if_names[i];
		port = &global.l3fwd_pktios[i];
		/* start pktio */
		if (odp_pktio_start(port->pktio)) {
			printf("unable to start pktio: %s\n", if_name);
			exit(1);
		}

		sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
			port->mac_addr.addr[0],
			port->mac_addr.addr[1],
			port->mac_addr.addr[2],
			port->mac_addr.addr[3],
			port->mac_addr.addr[4],
			port->mac_addr.addr[5]);
		printf("start pktio: %s, mac %s\n", if_name, buf);
	}

	odp_barrier_init(&barrier, nb_worker + 1);

	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.start    = run_worker;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;

	memset(thread_tbl, 0, sizeof(thread_tbl));
	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < nb_worker; i++) {
		struct thread_arg_s *arg;
		odp_cpumask_t thr_mask;

		arg = &global.worker_args[i];
		odp_cpumask_zero(&thr_mask);
		odp_cpumask_set(&thr_mask, cpu);
		thr_params.arg = arg;
		odph_odpthreads_create(&thread_tbl[i], &thr_mask,
				       &thr_params);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	print_speed_stats(nb_worker, args->duration, PRINT_INTERVAL);
	exit_threads = 1;

	/* wait for other threads to join */
	for (i = 0; i < nb_worker; i++)
		odph_odpthreads_join(&thread_tbl[i]);

	for (i = 0; i < args->if_count; ++i) {
		struct l3fwd_pktio_s *port;

		port = &global.l3fwd_pktios[i];

		ret   = odp_pktio_stop(port->pktio);
		if (ret) {
			printf("Error: unable to stop %s\n",
			       args->if_names[i]);
			exit(EXIT_FAILURE);
		}

		ret   = odp_pktio_close(port->pktio);
		if (ret) {
			printf("Error: unable to close %s\n",
			       args->if_names[i]);
			exit(EXIT_FAILURE);
		}
	}

	/* if_names share a single buffer, so only one free */
	free(args->if_names[0]);

	for (i = 0; i < MAX_NB_ROUTE; i++)
		free(args->route_str[i]);

	if (odp_pool_destroy(pool)) {
		printf("Error: pool destroy\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		printf("Error: term local\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		printf("Error: term global\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
