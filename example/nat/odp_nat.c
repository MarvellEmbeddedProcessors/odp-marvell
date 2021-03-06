/* Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_nat.c  ODP basic NAT application
 */

/** enable strtok */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <odp_api.h>
#include <odp_debug_internal.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>
#include <odp/helper/tcp.h>
#include <odp/helper/icmp.h>
#include <odp_packet_internal.h>

#include "xxhash.h"

/** @def MAX_WORKERS
 * @brief Maximum number of worker threads
 */
#define MAX_WORKERS            32

/** @def SHM_PKT_POOL_SIZE
 * @brief Size of the shared memory block
 */
#define SHM_PKT_POOL_SIZE      1024

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE  1856

/** @def MAX_PKT_BURST
 * @brief Maximum number of packet in a burst
 */
#define MAX_PKT_BURST          64

/** Maximum number of pktio queues per interface */
#define MAX_QUEUES             32

/** Maximum number of pktio interfaces */
#define MAX_PKTIOS             4

#define NAT_TBL_SIZE           (64 * 1024)
#define NAT_TBL_DEPTH          4

#define IP_MAP_TBL_SIZE        128

#define NAT_HASH_SEED          0x20141025

#define PREFETCH_SHIFT         3

#define ODP_NAT_MAX_WAN_IP     	8
#define ODP_NAT_MAX_ETH_IF     	2
#define ODP_NAT_DEF_DEV_ID     	8
#define DSA_SRC_PORT_CPU       	31

#define VID_MASK               	0xFFF
#define DEV_ID_MASK            	0x1F

#define MAX_STRING  			32

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

typedef enum {
	DATA_PLANE_FROM_LAN,
	DATA_PLANE_FROM_WAN,
	CONTROL_PLANE_TO_CPU_LAN,
	CONTROL_PLANE_TO_CPU_WAN,
	CONTROL_PLANE_FROM_CPU_LAN,
	CONTROL_PLANE_FROM_CPU_WAN,
	PKT_TYPE_UNKNOWN,
} odph_nat_pkt_type_e;

typedef struct odph_nat_node_t {
	struct odph_nat_node_t *prev;
	struct odph_nat_node_t *next;
	uint32_t         value;
} odph_nat_node_t;

typedef struct {
	odp_rwlock_t lock;
	odph_nat_node_t* head;
	odph_nat_node_t* node_buffer_head;
	uint32_t start_value;
	uint32_t end_value;
} odph_nat_pool_t;

typedef struct {
	odph_nat_pool_t udp_port_pool;
	odph_nat_pool_t tcp_port_pool;
	odph_nat_pool_t icmp_id_pool;
	uint32_t valid;
	uint32_t wan_ip;
} odph_nat_wan_pool_t;

/**
 * Parsed command line application arguments
 */
typedef struct {
	int cpu_count;
	int if_count;		/**< Number of total interfaces to be used */
	int if_phy_count;	/**< Number of physical interfaces to be used */
	int if_wan_count;	/**< Number of wan vlans to be used */
	int num_workers;	/**< Number of worker threads */
	char **if_names;	/**< Array of pointers to interface names */

	int time;		/**< Time in seconds to run. */
	int accuracy;		/**< Number of seconds to get and print statistics */
	char *if_str;		/**< Storage for interface names */
	char *if_wan_str;	/**< Storage for wan vlans */
	char  tap_str[128];    /**< Storage for tap interface names */
	int error_check;        /**< Check packet errors */

	uint32_t aging_time; /* aging time for DNAT entries */
	int dsa_mode;
	int debug_mode;
	uint16_t lan_vid;
	uint16_t wan_vid[ODP_NAT_MAX_WAN_IP];
	int src_dev_id;
} appl_args_t;

typedef struct ipv4_5tuple_t {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  protocol;
} ipv4_5tuple_t;

typedef struct snat_entry_t {
	uint32_t local_subnet;
	uint32_t local_mask;
	uint32_t public_subnet;
	uint32_t public_mask;
	uint32_t valid;
	odph_nat_wan_pool_t* pool;
} ip_mapping_entry_t;

struct nat_entry_t;
typedef struct nat_entry_t {
	ipv4_5tuple_t ipv4_5tuple;
	uint16_t     	target_port; 	/* For SNAT, it is source port, for DNAT, it is dest port */
	uint32_t     	target_ip; 	/* For SNAT, it is source ip, for DNAT, it is dest ip */
	struct nat_entry_t *reverse_nat_entry;
	uint32_t     	valid;
} nat_entry_t;

/**
 * Statistics
 */
typedef union {
	struct {
		/** Number of forwarded packets */
		uint64_t packets;
		/** Packets dropped due to receive error */
		uint64_t rx_drops;
		/** Packets dropped due to transmit error */
		uint64_t tx_drops;
	} s;

	uint8_t padding[ODP_CACHE_LINE_SIZE];
} stats_t ODP_ALIGNED_CACHE;

typedef struct {
	odp_pktio_t rx_pktio;
	odp_pktio_t tx_pktio;
	odp_pktin_queue_t pktin;
	odp_pktout_queue_t pktout;
	odp_queue_t rx_queue;
	odp_queue_t tx_queue;
	int rx_idx;
	int tx_idx;
	int rx_queue_idx;
	int tx_queue_idx;
} odp_nat_pktio_t;

/**
 * Thread specific arguments
 */
typedef struct thread_args_t {
	int thr_idx;
	int num_pktio;
	odp_nat_pktio_t pktio[MAX_PKTIOS];
	stats_t *stats;	/**< Pointer to per thread stats */
} thread_args_t;

/**
 * Grouping of all global data
 */
typedef struct {
	/** Per thread packet stats */
	stats_t stats[MAX_WORKERS];
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];

	/** Table of dst ports */
	int dst_port[MAX_PKTIOS];
	/** Table of pktio handles */
	struct {
		odp_pktio_t pktio;
		odp_pktin_queue_t pktin[MAX_QUEUES];
		odp_pktout_queue_t pktout[MAX_QUEUES];
		odp_queue_t rx_q[MAX_QUEUES];
		odp_queue_t tx_q[MAX_QUEUES];
		int num_rx_thr;
		int num_tx_thr;
		int num_rx_queue;
		int num_tx_queue;
		int next_rx_queue;
		int next_tx_queue;
	} pktios[MAX_PKTIOS];
	nat_entry_t snat_tbl[NAT_TBL_SIZE][NAT_TBL_DEPTH]; /**< SNAT table */
	nat_entry_t dnat_tbl[NAT_TBL_SIZE][NAT_TBL_DEPTH]; /**< DNAT table */
	odp_rwlock_t snat_lock;
	odp_rwlock_t dnat_lock;
	ip_mapping_entry_t ip_map_tbl[IP_MAP_TBL_SIZE];
	odph_nat_wan_pool_t wan_pool[ODP_NAT_MAX_WAN_IP];
} args_t;

typedef enum {
    DSA_TO_CPU_E = 0,
    DSA_FROM_CPU_E,
    DSA_TO_ANALYSER_E,
    DSA_FORWARD_E
} DSA_CMD;

typedef struct {
	uint8_t src_dev; //bit[0..4]
	uint8_t src_port;//bit[3..7]
	uint16_t vid;   // bit[0..11]
	uint8_t resv1;
	uint8_t resv2;
	uint8_t resv3;
	uint8_t dst_dev; //bit[0..4]
} odph_dsa_t;

typedef struct ODP_PACKED {
	odph_ethaddr_t dst; /**< Destination address */
	odph_ethaddr_t src; /**< Source address */
	odph_dsa_t     dsa;
	odp_u16be_t type;   /**< EtherType */
} odph_dsa_ethhdr_t;

static int exit_threads;	/**< Break workers loop if set to 1 */

/** Global pointer to args */
static args_t *gbl_args;
/** Global barrier to synchronize main and workers */
static odp_barrier_t barrier;

static uint16_t net_cksum(uint8_t *ptr, int len)
{
	unsigned long xsum;
	uint16_t *p = (uint16_t *)ptr;

	xsum = 0;
	while (len-- > 0)
		xsum += *p++;
	xsum = (xsum & 0xffff) + (xsum >> 16);
	xsum = (xsum & 0xffff) + (xsum >> 16);
	return xsum & 0xffff;
}

static uint32_t ipv4_aton(char *ip_str)
{
	uint8_t byte1 = 0, byte2 = 0, byte3 = 0, byte4 = 0;
	char *token;

	token = strtok(ip_str, ".");
	if (token != NULL)
		byte1 = (uint8_t)atoi(token);
	token = strtok(NULL, ".");
	if (token != NULL)
		byte2 = (uint8_t)atoi(token);
	token = strtok(NULL, ".");
	if (token != NULL)
		byte3 = (uint8_t)atoi(token);
	token = strtok(NULL, ".");
	if (token != NULL)
		byte4 = (uint8_t)atoi(token);
	return (byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4;
}

static char *ipv4_str(char *b, uint32_t *ip_addr)
{
	sprintf(b, "%d.%d.%d.%d",
		0xFF & (*ip_addr >> 24),
		0xFF & (*ip_addr >> 16),
		0xFF & (*ip_addr >>  8),
		0xFF & (*ip_addr >>  0));
	return b;
}
/**
 * Drop packets which input parsing marked as containing errors.
 *
 * Frees packets with error and modifies pkt_tbl[] to only contain packets with
 * no detected errors.
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

	for (i = 0, j = 0; i < num; ++i) {
		pkt = pkt_tbl[i];

		if (odp_unlikely(odp_packet_has_error(pkt))) {
			odp_packet_free(pkt); /* Drop */
			dropped++;
		} else if (odp_unlikely(i != j++)) {
			pkt_tbl[j - 1] = pkt;
		}
	}

	return dropped;
}

static inline void init_pool(odph_nat_pool_t* pool, uint16_t start, uint16_t end)
{
	uint16_t i;
	odph_nat_node_t *ptr = NULL;
	odph_nat_node_t * prev = NULL;
	odph_nat_node_t * next = NULL;

	odp_rwlock_init(&pool->lock);

	pool->node_buffer_head = (odph_nat_node_t*)malloc(sizeof(odph_nat_node_t) * (end - start + 1));
	if (!pool->node_buffer_head) {
		printf("Failed to allocate memory for pool\n");
		return;
	}

	pool->head = pool->node_buffer_head;
	pool->head->value = start;
	pool->head->prev = NULL;
	pool->head->next = pool->head + 1;
	pool->start_value = start;
	pool->end_value = end;

	for (i = start + 1, ptr = pool->head + 1; i <= end; i++, ptr++) {
		ptr->value = i;
		ptr->prev = ptr - 1;
		ptr->next = ptr + 1;
	}
	ptr->next = NULL;
}

static inline uint16_t allocate_node_for_pool(odph_nat_pool_t* pool)
{
	odph_nat_node_t* ptr = pool->head;

	odp_rwlock_write_lock(&pool->lock);
	if (pool->head) {
		pool->head = pool->head->next;
		pool->head->prev = NULL;
	}
	odp_rwlock_write_unlock(&pool->lock);

	if (ptr)
		return ptr->value;
	else
		return 0;
}

static inline void release_node_for_pool(odph_nat_pool_t* pool, uint16_t value)
{
	odph_nat_node_t* ptr = pool->node_buffer_head + value - pool->start_value;

	odp_rwlock_write_lock(&pool->lock);
	if (pool->head) {
		ptr->next = pool->head;
		pool->head->prev = ptr;
		ptr->prev = NULL;
		pool->head = ptr;
	} else {
		pool->head = ptr;
		pool->head->prev = pool->head->next = NULL;
	}
	odp_rwlock_write_unlock(&pool->lock);
}

static inline odph_nat_wan_pool_t* alloc_wan_pool(uint32_t wan_ip, uint32_t start, uint32_t end)
{
	int i;

	for (i = 0; i < ODP_NAT_MAX_WAN_IP; i++) {
		if (gbl_args->wan_pool[i].valid && (gbl_args->wan_pool[i].wan_ip == wan_ip)) {
			return &gbl_args->wan_pool[i];
		}
	}
	for (i = 0; i < ODP_NAT_MAX_WAN_IP; i++) {
		if (!gbl_args->wan_pool[i].valid) {
			gbl_args->wan_pool[i].valid = 1;
			gbl_args->wan_pool[i].wan_ip = wan_ip;
			init_pool(&gbl_args->wan_pool[i].udp_port_pool, start, end);
			init_pool(&gbl_args->wan_pool[i].tcp_port_pool, start, end);
			init_pool(&gbl_args->wan_pool[i].icmp_id_pool, start, end);
			return &gbl_args->wan_pool[i];
		}
	}
	printf("Too many wan ip configured, max number supported is %d\n", ODP_NAT_MAX_WAN_IP);
	return NULL;
}

static uint32_t ip_table_lookup(uint32_t ip)
{
	int k;
	ip_mapping_entry_t *iptbl;

	//printf("ip_table_lookup: ip = %08x\n", ip);
	for (k = 0; k < IP_MAP_TBL_SIZE; k++) {
		iptbl = &gbl_args->ip_map_tbl[k];
/*
		printf("ip_table entry: %d %08x %08x %08x %08x <- %d\n", iptbl->valid, iptbl->local_subnet,
			iptbl->local_mask, iptbl->public_subnet, iptbl->public_mask, k);
*/
		if (iptbl->valid && ((ip & iptbl->local_mask) == (iptbl->local_subnet & iptbl->local_mask))) {
			return (iptbl->public_subnet & iptbl->public_mask) | (ip & (~iptbl->public_mask));
		}
	}

	return 0;
}

static odph_nat_wan_pool_t* ip_table_lookup_pool(uint32_t ip)
{
	int k;
	ip_mapping_entry_t *iptbl;

	//printf("ip_table_lookup: ip = %08x\n", ip);
	for (k = 0; k < IP_MAP_TBL_SIZE; k++) {
		iptbl = &gbl_args->ip_map_tbl[k];
		//printf("ip_table_add_entry: %d %08x %08x %08x %08x <- %d\n", iptbl->valid, iptbl->local_subnet, iptbl->local_mask, iptbl->public_subnet, iptbl->public_mask, k);

		if (iptbl->valid && ((ip & iptbl->local_mask) == (iptbl->local_subnet & iptbl->local_mask))) {
			return (iptbl->pool);
		}
	}

	return 0;
}

static void ip_table_add_entry(uint32_t subnet, uint32_t mask, uint32_t public_subnet, uint32_t public_mask)
{
	int k;
	ip_mapping_entry_t *iptbl;
	char subnet_str[MAX_STRING];
	char mask_str[MAX_STRING];
	char pub_subnet_str[MAX_STRING];
	char pub_mask_str[MAX_STRING];

	for (k = 0; k < IP_MAP_TBL_SIZE; k++) {
		iptbl = &gbl_args->ip_map_tbl[k];
		if (!iptbl->valid) {
			iptbl->valid = 1;
			iptbl->local_mask = mask;
			iptbl->local_subnet = subnet;
			iptbl->public_subnet = public_subnet;
			iptbl->public_mask = public_mask;
			iptbl->pool = alloc_wan_pool(public_subnet, 1024, 65534);
			printf("ip_table_add_entry: %32s %32s %32s %32s -> %d\n",
			       ipv4_str(subnet_str, &subnet), ipv4_str(mask_str, &mask),
			       ipv4_str(pub_subnet_str, &public_subnet),
			       ipv4_str(pub_mask_str, &public_mask), k);
//		printf("ip_table_add_entry: %08x %08x %08x %08x -> %d\n",
//				subnet, mask, public_subnet, public_mask, k);
			break;
		}
	}
}

static nat_entry_t* dnat_tbl_add_entry(ipv4_5tuple_t* ipv4_5tuple, uint32_t target_ip, uint16_t port, nat_entry_t* snat_ptr)
{
	uint32_t hash_index;
	uint8_t i;
	nat_entry_t *entry;
	char src_ip_str[MAX_STRING];
	char dst_ip_str[MAX_STRING];

	hash_index = XXH32((void *)ipv4_5tuple, sizeof(ipv4_5tuple_t), NAT_HASH_SEED) & (NAT_TBL_SIZE - 1);
	for (i = 0; i < NAT_TBL_DEPTH; i++) {
		odp_rwlock_write_lock(&gbl_args->dnat_lock);
		entry = &gbl_args->dnat_tbl[hash_index][i];

		if (entry->valid) {
			odp_rwlock_write_unlock(&gbl_args->dnat_lock);
			if (0 == memcmp(ipv4_5tuple, &entry->ipv4_5tuple, sizeof(ipv4_5tuple_t))) {
				return entry;
			}
		} else {
			entry->valid = 1;
			entry->ipv4_5tuple = *ipv4_5tuple;
			entry->target_ip = target_ip;
			entry->target_port = port;
			entry->reverse_nat_entry = snat_ptr;
			odp_rwlock_write_unlock(&gbl_args->dnat_lock);
			return entry;
		}
	}
	if (odp_unlikely(i == NAT_TBL_DEPTH))
		printf("DNAT hash table conflicts: %32s %d %32s %d %d -> %u\n",
		       ipv4_str(src_ip_str, &ipv4_5tuple->src_ip), ipv4_5tuple->src_port,
		       ipv4_str(dst_ip_str, &ipv4_5tuple->dst_ip), ipv4_5tuple->dst_port,
		       ipv4_5tuple->protocol, hash_index);
	return NULL;
}

static void *odp_nat_packet_l3_ptr(odp_packet_t pkt, uint32_t *offset, uint16_t *ethtype)
{
	odph_ethhdr_t *eth;
	odph_vlanhdr_t *vlan;
	uint8_t *parseptr;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (odp_packet_has_eth(pkt)) {
		*offset = sizeof(odph_ethhdr_t);
		eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
		*ethtype = odp_be_to_cpu_16(eth->type);
		parseptr = (uint8_t *)(eth + 1);

		if (gbl_args->appl.dsa_mode) {
			odph_dsa_ethhdr_t *eth;
			*offset = sizeof(odph_dsa_ethhdr_t);
			eth = (odph_dsa_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
			*ethtype = odp_be_to_cpu_16(eth->type);
			parseptr = (uint8_t *)(eth + 1);
		} else {
			odph_ethhdr_t *eth;
		        *offset = sizeof(odph_ethhdr_t);
		        eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
		        *ethtype = odp_be_to_cpu_16(eth->type);
		        parseptr = (uint8_t *)(eth + 1);
		}

		/* Parse the VLAN header(s), if present */
		if (odp_unlikely((*ethtype) == ODPH_ETHTYPE_VLAN_OUTER)) {
			vlan = (odph_vlanhdr_t *)parseptr;
			*ethtype = odp_be_to_cpu_16(vlan->type);
			(*offset) += 4;
		}
		if (odp_unlikely((*ethtype) == ODPH_ETHTYPE_VLAN)) {
			vlan = (odph_vlanhdr_t *)parseptr;
			*ethtype = odp_be_to_cpu_16(vlan->type);
			(*offset) += 4;
		}
		pkt_hdr->p.l3_offset = *offset;
		if (odp_likely((*ethtype) == ODPH_ETHTYPE_IPV4))
			pkt_hdr->p.input_flags.ipv4 = 1;
		else if ((*ethtype) == ODPH_ETHTYPE_IPV6)
			pkt_hdr->p.input_flags.ipv6 = 1;

		return odp_packet_offset(pkt, *offset, NULL, NULL);
	}
	return NULL;
}

static void *odp_nat_packet_l4_ptr(odp_packet_t pkt, void *l3_hdr, uint32_t l3_offset, uint16_t ethtype)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (ethtype == ODPH_ETHTYPE_IPV4) {
		odph_ipv4hdr_t *ipv4hdr = (odph_ipv4hdr_t *)l3_hdr;
		uint8_t ihl = ODPH_IPV4HDR_IHL(ipv4hdr->ver_ihl);
		uint8_t l4_protol = ipv4hdr->proto;

		pkt_hdr->p.l4_offset = pkt_hdr->p.l3_offset + (ihl << 2);

		if (odp_likely(l4_protol == ODPH_IPPROTO_UDP))
			pkt_hdr->p.input_flags.udp = 1;
		else if (l4_protol == ODPH_IPPROTO_TCP)
			pkt_hdr->p.input_flags.tcp = 1;

		return (odph_ipv4hdr_t *)odp_packet_offset(pkt, l3_offset + ihl * 4, NULL, NULL);
	}
	return NULL;
}

static int process_tocpu_lan(odp_packet_t pkt)
{
    odp_nat_pktio_t pktio;
    int tx_idx;
    odph_ethaddr_t macaddr[2];

    tx_idx = gbl_args->appl.if_phy_count;

    pktio.tx_idx = tx_idx;
    pktio.pktout = gbl_args->pktios[tx_idx].pktout[0];
    pktio.tx_queue = gbl_args->pktios[tx_idx].tx_q[0];
    pktio.tx_pktio = gbl_args->pktios[tx_idx].pktio;

    if(odp_packet_copy_to_mem(pkt, 0, 2 * sizeof(odph_ethaddr_t), &macaddr) != 0) {
        return 1;
    }

    odp_packet_pull_head(pkt, sizeof(odph_dsa_t));

    if(odp_packet_copy_from_mem(pkt, 0, 2 * sizeof(odph_ethaddr_t), &macaddr) != 0) {
        return 1;
    }

    if (gbl_args->appl.debug_mode) {
        int j;
        uint8_t* data = (uint8_t *)odp_packet_l2_ptr(pkt, NULL);
        printf("Sending to %s\n", gbl_args->appl.if_names[tx_idx]);

        for (j = 0; j < 64; j++) {
            printf("%02x ", data[j]);
        }
        printf("\n");
    }

    if (1 == odp_pktout_send(pktio.pktout, &pkt, 1))
        return 2;
    else
        return 1;
}

static int process_tocpu_wan(odp_packet_t pkt)
{
    odp_nat_pktio_t pktio;
    int tx_idx;
    odph_ethaddr_t macaddr[2];
    odph_dsa_ethhdr_t *eth;
    int i;

    eth = (odph_dsa_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);

    for (i = 0; i < gbl_args->appl.if_wan_count; i++) {
        if ((ntohs(eth->dsa.vid) & VID_MASK) == gbl_args->appl.wan_vid[i]) {
            tx_idx = gbl_args->appl.if_phy_count + i + 1;
            break;
        }
    }

    pktio.tx_idx = tx_idx;
    pktio.pktout = gbl_args->pktios[tx_idx].pktout[0];
    pktio.tx_queue = gbl_args->pktios[tx_idx].tx_q[0];
    pktio.tx_pktio = gbl_args->pktios[tx_idx].pktio;

    if(odp_packet_copy_to_mem(pkt, 0, 2 * sizeof(odph_ethaddr_t), &macaddr) != 0) {
        return 1;
    }

    odp_packet_pull_head(pkt, sizeof(odph_dsa_t));

    if(odp_packet_copy_from_mem(pkt, 0, 2 * sizeof(odph_ethaddr_t), &macaddr) != 0) {
        return 1;
    }

    if (gbl_args->appl.debug_mode) {
        int j;
        uint8_t* data = (uint8_t *)odp_packet_l2_ptr(pkt, NULL);
        printf("Sending to %s\n", gbl_args->appl.if_names[tx_idx]);

        for (j = 0; j < 64; j++) {
            printf("%02x ", data[j]);
        }
        printf("\n");
    }

    if (1 == odp_pktout_send(pktio.pktout, &pkt, 1))
        return 2;
    else
        return 1;
}

static int process_fromcpu_lan(odp_packet_t pkt)
{
    odp_nat_pktio_t pktio;
    odph_dsa_t   dsaFill;
    odph_ethaddr_t macaddr[2];

    memset(&dsaFill, 0,sizeof(odph_dsa_t));
    // bit[31,30]:11 (forward), bit[28:24]:01000 (src_dev)
    dsaFill.src_dev = 0xC0;
    dsaFill.src_dev |= gbl_args->appl.src_dev_id & DEV_ID_MASK;
    // bit[23,19]:63(src_port),
    dsaFill.src_port = DSA_SRC_PORT_CPU << 3;
    dsaFill.resv1 = 0x20; //This is Bit 5 of src port
    dsaFill.vid  = htons((1 << 12) | gbl_args->appl.lan_vid);

    pktio.tx_idx = 0;
    pktio.pktout = gbl_args->pktios[0].pktout[0];
    pktio.tx_queue = gbl_args->pktios[0].tx_q[0];
    pktio.tx_pktio =gbl_args->pktios[0].pktio;

    if(odp_packet_copy_to_mem(pkt, 0, 2 * sizeof(odph_ethaddr_t), &macaddr) != 0) {
        return 1;
    }

    odp_packet_push_head(pkt, sizeof(odph_dsa_t));

    if(odp_packet_copy_from_mem(pkt, 0, 2 * sizeof(odph_ethaddr_t), &macaddr) != 0) {
        return 1;
    }

    if (odp_packet_copy_from_mem(pkt, 2 * sizeof(odph_ethaddr_t), sizeof(odph_dsa_t), &dsaFill) != 0) {
        return 1;
    }

    if (gbl_args->appl.debug_mode) {
        int j;
        uint8_t* data = (uint8_t *)odp_packet_l2_ptr(pkt, NULL);
        printf("Sending to %s\n", gbl_args->appl.if_names[pktio.tx_idx]);

        for (j = 0; j < 64; j++) {
            printf("%02x ", data[j]);
        }
        printf("\n");
    }

    if (1 == odp_pktout_send(pktio.pktout, &pkt, 1))
        return 2;
    else
        return 1;
}

static int process_fromcpu_wan(odp_packet_t pkt, odp_nat_pktio_t* rx_pktio)
{
    odp_nat_pktio_t pktio;
    odph_dsa_t   dsaFill;
    odph_ethaddr_t macaddr[2];
    int tx_idx;

    memset(&dsaFill, 0,sizeof(odph_dsa_t));
    // bit[31,30]:11 (forward), bit[28:24]:01000 (src_dev)
    dsaFill.src_dev = 0xC0;
    dsaFill.src_dev |= gbl_args->appl.src_dev_id & DEV_ID_MASK;
    // bit[23,19]:63(src_port),
    dsaFill.src_port = DSA_SRC_PORT_CPU << 3;
    dsaFill.resv1 = 0x20; //This is Bit 5 of src port
    dsaFill.vid  = htons((1 << 12) | gbl_args->appl.wan_vid[rx_pktio->rx_idx - gbl_args->appl.if_phy_count - 1]);

    tx_idx = gbl_args->appl.if_phy_count - 1;

    pktio.tx_idx = tx_idx;
    pktio.pktout = gbl_args->pktios[tx_idx].pktout[0];
    pktio.tx_queue = gbl_args->pktios[tx_idx].tx_q[0];
    pktio.tx_pktio =gbl_args->pktios[tx_idx].pktio;

    if(odp_packet_copy_to_mem(pkt, 0, 2 * sizeof(odph_ethaddr_t), &macaddr) != 0) {
        return 1;
    }

    odp_packet_push_head(pkt, sizeof(odph_dsa_t));

    if(odp_packet_copy_from_mem(pkt, 0, 2 * sizeof(odph_ethaddr_t), &macaddr) != 0) {
        return 1;
    }

    if (odp_packet_copy_from_mem(pkt, 2 * sizeof(odph_ethaddr_t), sizeof(odph_dsa_t), &dsaFill) != 0) {
        return 1;
    }

    if (gbl_args->appl.debug_mode) {
        int j;
        uint8_t* data = (uint8_t *)odp_packet_l2_ptr(pkt, NULL);
        printf("Sending to %s\n", gbl_args->appl.if_names[pktio.tx_idx]);

        for (j = 0; j < 64; j++) {
            printf("%02x ", data[j]);
        }
        printf("\n");
    }

    if (1 == odp_pktout_send(pktio.pktout, &pkt, 1))
        return 2;
    else
        return 1;
}

static int do_snat(odp_packet_t pkt, nat_entry_t tbl[][NAT_TBL_DEPTH])
{
	unsigned i, j;
	odph_ipv4hdr_t *ipv4hdr;
	odph_udphdr_t  *udphdr;
	odph_icmphdr_t *icmphdr;
	odph_tcphdr_t  *tcphdr;
	uint32_t ip;
	uint16_t ethtype;
	uint32_t l3_offset;
	ipv4_5tuple_t snat_ipv4, dnat_ipv4;
	uint32_t hash_index;
	ip_mapping_entry_t *iptbl;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	odph_dsa_ethhdr_t *eth;
	unsigned char dev_id;
	char src_ip_str[MAX_STRING];
	char dst_ip_str[MAX_STRING];

	ipv4hdr = (odph_ipv4hdr_t *)odp_nat_packet_l3_ptr(pkt, &l3_offset, &ethtype);

	//For IPv6, don't do anything
	if (pkt_hdr->p.input_flags.ipv6)
		return 0;

	// udphdr is L4 header, could be udp, tcp or icmp header
	udphdr = (odph_udphdr_t *)odp_nat_packet_l4_ptr(pkt, ipv4hdr, l3_offset, ethtype);
	icmphdr = (odph_icmphdr_t*)udphdr;
	tcphdr = (odph_tcphdr_t*)udphdr;

	if (gbl_args->appl.dsa_mode) {
		odph_dsa_ethhdr_t *eth;
		unsigned char src_dev_id, dst_dev_id;
		eth = (odph_dsa_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
		// swap Source and Dest DevID of DSA tag
		//printf("do_snat RX: dsa.word0=0x%x, dsa.word1=0x%x\n",eth->dsa.word[0],eth->dsa.word[1]);
		src_dev_id = eth->dsa.src_dev & DEV_ID_MASK;
		dst_dev_id = eth->dsa.dst_dev & DEV_ID_MASK;
		eth->dsa.src_dev &= 0xE0;
		eth->dsa.dst_dev &= 0xE0;
		eth->dsa.src_dev |= dst_dev_id;
		eth->dsa.dst_dev |= src_dev_id;
		//printf("do_snat TX: dsa.word0=0x%x, dsa.word1=0x%x\n",eth->dsa.word[0],eth->dsa.word[1]);
	}

	if (ipv4hdr && udphdr) {
		snat_ipv4.src_ip = ntohl(ipv4hdr->src_addr);
		snat_ipv4.dst_ip = ntohl(ipv4hdr->dst_addr);
		snat_ipv4.protocol = ipv4hdr->proto;
		if (odp_likely(snat_ipv4.protocol != ODPH_IPPROTO_ICMP)) {
			snat_ipv4.src_port = ntohs(udphdr->src_port);
			snat_ipv4.dst_port = ntohs(udphdr->dst_port);
		} else {
			//Only handle echo request and reply
			if ((icmphdr->type != 8) &&  (icmphdr->type != 0))
				return 1;
			if (icmphdr->code)
				return 1;
			snat_ipv4.src_port = ntohs(icmphdr->un.echo.id);
			snat_ipv4.dst_port = 0;
		}

		hash_index = XXH32((void*)&snat_ipv4, sizeof(ipv4_5tuple_t), NAT_HASH_SEED) & (NAT_TBL_SIZE-1);

		for (j = 0; j < NAT_TBL_DEPTH; j++) {
		    odp_rwlock_write_lock(&gbl_args->snat_lock);
			if (tbl[hash_index][j].valid) {
				odp_rwlock_write_unlock(&gbl_args->snat_lock);
				// Already there
				if (0 == memcmp(&snat_ipv4, &tbl[hash_index][j].ipv4_5tuple, sizeof(ipv4_5tuple_t))) {
					if (gbl_args->appl.debug_mode)
						printf("Found in snat table: %08x %d %08x %d %d %08x -> %d %d\n", snat_ipv4.src_ip, snat_ipv4.src_port, snat_ipv4.dst_ip, snat_ipv4.dst_port, snat_ipv4.protocol, tbl[hash_index][j].target_ip, hash_index, j);

					if (tbl[hash_index][j].target_ip) {

						switch (snat_ipv4.protocol) {
							case ODPH_IPPROTO_UDP:
								ipv4hdr->src_addr = ntohl(tbl[hash_index][j].target_ip);
								udphdr->src_port = ntohs(tbl[hash_index][j].target_port);
								udphdr->chksum = 0;
#if !defined(ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT) || (ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT == 0)
								odph_udp_chksum_set(pkt);
#endif
								break;
							case ODPH_IPPROTO_TCP:
								ipv4hdr->src_addr = ntohl(tbl[hash_index][j].target_ip);
								tcphdr->src_port = ntohs(tbl[hash_index][j].target_port);
								tcphdr->cksm = 0;
#if !defined(ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT) || (ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT == 0)
								odph_tcp_chksum_set(pkt);
#endif
								break;
							case ODPH_IPPROTO_ICMP:
								ipv4hdr->src_addr = ntohl(tbl[hash_index][j].target_ip);
								icmphdr->un.echo.id = ntohs(tbl[hash_index][j].target_port);
								icmphdr->chksum = 0;
								icmphdr->chksum = ~net_cksum((uint8_t *)icmphdr, (ntohs(ipv4hdr->tot_len) - ODPH_IPV4HDR_LEN) >> 1);
								break;
							default:
								break;
						}
						ipv4hdr->chksum = 0;
#if !defined(ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT) || (ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT == 0)
						odph_ipv4_csum_update(pkt);
#endif
					}
					break;
				}
			} else {
				odph_nat_wan_pool_t* port_pool = NULL;

				//odp_rwlock_write_unlock(&gbl_args->snat_lock);
				// First packet, Found empty position
				// 1. Search the IP mapping entry
				tbl[hash_index][j].target_ip = ip_table_lookup(snat_ipv4.src_ip);
				//printf("tbl[hash_index][j].target_ip=0x%x\n", tbl[hash_index][j].target_ip);

				// No match in IP table, probably control plane packets, drop it
				if (!tbl[hash_index][j].target_ip) {
					odp_rwlock_write_unlock(&gbl_args->snat_lock);
					return 1;
				}
				// 2. Add into SNAT table
				tbl[hash_index][j].valid = 1;
				tbl[hash_index][j].ipv4_5tuple = snat_ipv4;
				// Modify the local source port to public source port
				port_pool = ip_table_lookup_pool(snat_ipv4.src_ip);
				switch (snat_ipv4.protocol) {
					case ODPH_IPPROTO_UDP:
						tbl[hash_index][j].target_port = allocate_node_for_pool(&port_pool->udp_port_pool);
						break;
					case ODPH_IPPROTO_TCP:
						tbl[hash_index][j].target_port = allocate_node_for_pool(&port_pool->tcp_port_pool);
						break;
					case ODPH_IPPROTO_ICMP:
						tbl[hash_index][j].target_port = allocate_node_for_pool(&port_pool->icmp_id_pool);
						break;
					default:
						break;
				}
				odp_rwlock_write_unlock(&gbl_args->snat_lock);

				//if (j > 1)
				if (gbl_args->appl.debug_mode)
					printf("add to snat table: %08x %d %08x %d %d %08x -> %d %d\n", snat_ipv4.src_ip, snat_ipv4.src_port, snat_ipv4.dst_ip, snat_ipv4.dst_port, snat_ipv4.protocol, tbl[hash_index][j].target_ip, hash_index, j);

				if (tbl[hash_index][j].target_ip) {
					// 3. Add into DNAT table
					dnat_ipv4.src_ip = snat_ipv4.dst_ip;
					dnat_ipv4.src_port = snat_ipv4.dst_port;
					dnat_ipv4.dst_port = tbl[hash_index][j].target_port;
					dnat_ipv4.protocol = snat_ipv4.protocol;
					dnat_ipv4.dst_ip = tbl[hash_index][j].target_ip;
					if (snat_ipv4.protocol == ODPH_IPPROTO_ICMP) {
						dnat_ipv4.src_port = tbl[hash_index][j].target_port; //ID
						dnat_ipv4.dst_port = 0;
					}

					tbl[hash_index][j].reverse_nat_entry = dnat_tbl_add_entry(&dnat_ipv4, snat_ipv4.src_ip, snat_ipv4.src_port, &tbl[hash_index][j]);
					if (gbl_args->appl.debug_mode) {
						printf("add to dnat table: %08x %d %08x %d %d %08x -> %p\n", dnat_ipv4.src_ip, dnat_ipv4.src_port, dnat_ipv4.dst_ip, dnat_ipv4.dst_port, dnat_ipv4.protocol, snat_ipv4.src_ip, tbl[hash_index][j].reverse_nat_entry);
						printf("Chaning src IP from %08x to %08x, src port to %d\n", ipv4hdr->src_addr, ntohl(tbl[hash_index][j].target_ip), ntohs(tbl[hash_index][j].target_port));
					}

					// 4. DO NAT
					switch (snat_ipv4.protocol) {
						case ODPH_IPPROTO_UDP:
							ipv4hdr->src_addr = ntohl(tbl[hash_index][j].target_ip);
							udphdr->src_port = ntohs(tbl[hash_index][j].target_port);
							udphdr->chksum = 0;
#if !defined(ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT) || (ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT == 0)
							odph_udp_chksum_set(pkt);
#endif
							break;
						case ODPH_IPPROTO_TCP:
							ipv4hdr->src_addr = ntohl(tbl[hash_index][j].target_ip);
							tcphdr->src_port = ntohs(tbl[hash_index][j].target_port);
							tcphdr->cksm = 0;
#if !defined(ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT) || (ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT == 0)
							odph_tcp_chksum_set(pkt);
#endif
							break;
						case ODPH_IPPROTO_ICMP:
							ipv4hdr->src_addr = ntohl(tbl[hash_index][j].target_ip);
							icmphdr->un.echo.id = ntohs(tbl[hash_index][j].target_port);
							icmphdr->chksum = 0;
							icmphdr->chksum = ~net_cksum((uint8_t *)icmphdr, (ntohs(ipv4hdr->tot_len) - ODPH_IPV4HDR_LEN) >> 1);
							break;
						default:
							break;
					}
					ipv4hdr->chksum = 0;
#if !defined(ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT) || (ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT == 0)
					odph_ipv4_csum_update(pkt);
#endif
				}
				break;
			}
		}

		if (odp_unlikely(j == NAT_TBL_DEPTH)) {
			printf("no place for %08x %d %08x %d %d\n", snat_ipv4.src_ip, snat_ipv4.src_port, snat_ipv4.dst_ip, snat_ipv4.dst_port, snat_ipv4.protocol);
			return 1;
		}
	}

	return 0;
}

static int do_dnat(odp_packet_t pkt, nat_entry_t tbl[][NAT_TBL_DEPTH])
{
	unsigned i, j;
	odph_ipv4hdr_t *ipv4hdr;
	odph_udphdr_t  *udphdr;
	odph_icmphdr_t *icmphdr;
	odph_tcphdr_t  *tcphdr;
	uint32_t target_ip, hash_index;
	uint16_t ethtype, target_port;
	uint32_t l3_offset;
	ipv4_5tuple_t ipv4;
	odph_dsa_ethhdr_t *eth;
	unsigned char dev_id;

	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	ipv4hdr = (odph_ipv4hdr_t *)odp_nat_packet_l3_ptr(pkt, &l3_offset, &ethtype);
	//For IPv6, don't do anything
	if (pkt_hdr->p.input_flags.ipv6)
		return 0;

	udphdr = (odph_udphdr_t *)odp_nat_packet_l4_ptr(pkt, ipv4hdr, l3_offset, ethtype);
	icmphdr = (odph_icmphdr_t*)udphdr;
	tcphdr = (odph_tcphdr_t*)udphdr;

	if (ipv4hdr && udphdr) {

		ipv4.src_ip = ntohl(ipv4hdr->src_addr);
		ipv4.dst_ip = ntohl(ipv4hdr->dst_addr);
		ipv4.protocol = ipv4hdr->proto;
		if (odp_likely(ipv4.protocol != ODPH_IPPROTO_ICMP)) {
			ipv4.src_port = ntohs(udphdr->src_port);
			ipv4.dst_port = ntohs(udphdr->dst_port);
		} else {
			//Only handle echo request and reply
			if ((icmphdr->type != 8) &&  (icmphdr->type != 0))
				return 1;
			if (icmphdr->code)
				return 1;
			ipv4.src_port = ntohs(icmphdr->un.echo.id);
			ipv4.dst_port = 0;
		}

		hash_index = XXH32((void*)&ipv4, sizeof(ipv4_5tuple_t), NAT_HASH_SEED) & (NAT_TBL_SIZE - 1);

		for (j = 0; j < NAT_TBL_DEPTH; j++) {
			if (tbl[hash_index][j].valid) {
				if (0 == memcmp(&ipv4, &tbl[hash_index][j].ipv4_5tuple, sizeof(ipv4_5tuple_t))) {
					if (gbl_args->appl.debug_mode)
						printf("Found in dnat table: %08x %d %08x %d %d %08x -> %d %d\n", ipv4.src_ip, ipv4.src_port, ipv4.dst_ip, ipv4.dst_port, ipv4.protocol, tbl[hash_index][j].target_ip, hash_index, j);
					target_ip = tbl[hash_index][j].target_ip;
					target_port = tbl[hash_index][j].target_port;
					break;
				}
			} else
				break;
		}
		if (odp_unlikely((j == NAT_TBL_DEPTH) || (!tbl[hash_index][j].valid))) {
			if (gbl_args->appl.debug_mode)
				printf("Not found in dnat table: %08x %d %08x %d %d %d -> %d %d\n", ipv4.src_ip, ipv4.src_port, ipv4.dst_ip, ipv4.dst_port, ipv4.protocol, tbl[hash_index][j].valid, hash_index, j);
			return 1;
		}
		if (gbl_args->appl.debug_mode)
			printf("Changing dst address from %08x to %08x\n", ipv4hdr->dst_addr, htonl(target_ip));
		switch (ipv4.protocol) {
			case ODPH_IPPROTO_UDP:
				ipv4hdr->dst_addr = htonl(target_ip);
				udphdr->dst_port = htons(target_port);
				udphdr->chksum = 0;
#if !defined(ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT) || (ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT == 0)
				odph_udp_chksum_set(pkt);
#endif
				break;
			case ODPH_IPPROTO_TCP:
				ipv4hdr->dst_addr = htonl(target_ip);
				tcphdr->dst_port = htons(target_port);
				tcphdr->cksm = 0;
#if !defined(ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT) || (ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT == 0)
				odph_tcp_chksum_set(pkt);
#endif
				break;
			case ODPH_IPPROTO_ICMP:
				ipv4hdr->dst_addr = htonl(target_ip);
				icmphdr->un.echo.id = htons(target_port);
				icmphdr->chksum = 0;
				icmphdr->chksum = ~net_cksum((uint8_t *)icmphdr, (ntohs(ipv4hdr->tot_len) - ODPH_IPV4HDR_LEN) >> 1);
				break;
			default:
				break;
		}
		ipv4hdr->chksum = 0;
#if !defined(ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT) || (ODP_CONFIG_PKTIO_CSUM_OFF_SUPPORT == 0)
		odph_ipv4_csum_update(pkt);
#endif
	}
	return 0;
}

static inline odph_nat_pkt_type_e get_pkt_type(odp_packet_t pkt, odp_nat_pktio_t *pktio)
{
    odph_dsa_ethhdr_t *eth;

    if (!gbl_args->appl.dsa_mode) {
        // Only first interface is WAN
        if (pktio->rx_idx == 0)
        return DATA_PLANE_FROM_WAN;
        else
        return DATA_PLANE_FROM_LAN;
    } else {
        // From physical interfaces
        if (pktio->rx_idx < gbl_args->appl.if_phy_count) {
            eth = (odph_dsa_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);

            // Learn the device ID
            gbl_args->appl.src_dev_id = ntohs(eth->dsa.src_dev) & DEV_ID_MASK;

            // Data Plane
            if(((ntohs(eth->dsa.src_dev) >> 14) & 0x3) == DSA_FORWARD_E) {
                // If from LAN VID
                if ((ntohs(eth->dsa.vid) & VID_MASK) == gbl_args->appl.lan_vid)
                    return DATA_PLANE_FROM_LAN;
                else
                    return DATA_PLANE_FROM_WAN;
            } else { // Control Plane
                // If from LAN VID
                if ((ntohs(eth->dsa.vid) & VID_MASK) == gbl_args->appl.lan_vid)
                    return CONTROL_PLANE_TO_CPU_LAN;
                else
                    return CONTROL_PLANE_TO_CPU_WAN;
            }
        } else { // From TAP interfaces
            //the first tap interface is LAN
            if (pktio->rx_idx == gbl_args->appl.if_phy_count)
                return CONTROL_PLANE_FROM_CPU_LAN;
            else
                return CONTROL_PLANE_FROM_CPU_WAN;
        }
    }
    return PKT_TYPE_UNKNOWN;
}

static int process_pkt(odp_packet_t pkt_tbl[], unsigned num, odp_nat_pktio_t *pktio)
{
	odp_packet_t pkt;
	odp_packet_t send_pkt_tbl[MAX_PKT_BURST];
	unsigned i;
	int proceed = 0;//0: to send, 1: to drop, 2: been sent
	int sent = 0;

	for (i = 0, sent = 0; i < num; ++i) {
		pkt = pkt_tbl[i];
		if (num - i > PREFETCH_SHIFT)
			odp_packet_prefetch(pkt_tbl[i + PREFETCH_SHIFT], ODPH_ETHHDR_LEN, ODPH_IPV4HDR_LEN + 12);

		if (gbl_args->appl.debug_mode) {
			int j;
			uint8_t* data = (uint8_t *)odp_packet_l2_ptr(pkt, NULL);
			printf("Rx from interface %s\n", gbl_args->appl.if_names[pktio->rx_idx]);

			for (j = 0; j < 64; j++) {
				printf("%02x ", data[j]);
			}
			printf("\n");
		}

        switch (get_pkt_type(pkt, pktio)) {
            case DATA_PLANE_FROM_LAN:
                if (gbl_args->appl.debug_mode) {
                    printf("It is DATA_PLANE_FROM_LAN\n");
                }
                proceed = do_snat(pkt, gbl_args->snat_tbl);
                break;
            case DATA_PLANE_FROM_WAN:
                if (gbl_args->appl.debug_mode) {
                    printf("It is DATA_PLANE_FROM_WAN\n");
                }
                proceed = do_dnat(pkt, gbl_args->dnat_tbl);
                break;
            case CONTROL_PLANE_TO_CPU_LAN:
                if (gbl_args->appl.debug_mode) {
                    printf("It is CONTROL_PLANE_TO_CPU_LAN\n");
                }
                proceed = process_tocpu_lan(pkt);
                break;
            case CONTROL_PLANE_TO_CPU_WAN:
                if (gbl_args->appl.debug_mode) {
                    printf("It is CONTROL_PLANE_TO_CPU_WAN\n");
                }
                proceed = process_tocpu_wan(pkt);
                break;
            case CONTROL_PLANE_FROM_CPU_LAN:
                if (gbl_args->appl.debug_mode) {
                    printf("It is CONTROL_PLANE_FROM_CPU_LAN\n");
                }
                proceed = process_fromcpu_lan(pkt);
                break;
            case CONTROL_PLANE_FROM_CPU_WAN:
                if (gbl_args->appl.debug_mode) {
                    printf("It is CONTROL_PLANE_FROM_CPU_WAN\n");
                }
                proceed = process_fromcpu_wan(pkt, pktio);
                break;
            default:
                if (gbl_args->appl.debug_mode) {
                    printf("It is UNKNOWN TYPE\n");
                }
                odp_packet_free(pkt);
                break;
        }

        switch (proceed) {
            case 0:
                send_pkt_tbl[sent++] = pkt;
                if (gbl_args->appl.debug_mode) {
                    int j;
                    uint8_t* data = (uint8_t *)odp_packet_l2_ptr(pkt, NULL);
                    printf("After processing:\n");

                    for (j = 0; j < 64; j++) {
                        printf("%02x ", data[j]);
                    }
                    printf("\n");
                    printf("Sending to  %s\n", gbl_args->appl.if_names[pktio->tx_idx]);
                }
                break;
            case 1:
                odp_packet_free(pkt);
                if (gbl_args->appl.debug_mode)
                printf("Dropped\n");
                break;
            case 2:
                if (gbl_args->appl.debug_mode)
                printf("Sent to Control Plane\n");
                default:
                break;
        }
	}

	if (sent)
		sent = odp_pktout_send(pktio->pktout, send_pkt_tbl, sent);
	return sent;
}

/**
 * Packet IO worker thread accessing IO resources directly
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static int run_worker(void *arg)
{
	int pkts;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	odp_nat_pktio_t *cur_pktio;
	int dst_idx, num_pktio;
	odp_pktin_queue_t pktin;
	odp_pktout_queue_t pktout;
	int pktio = 0;
	thread_args_t *thr_args = arg;
	stats_t *stats = thr_args->stats;

	num_pktio = thr_args->num_pktio;
	dst_idx   = thr_args->pktio[pktio].tx_idx;
	pktin     = thr_args->pktio[pktio].pktin;
	pktout    = thr_args->pktio[pktio].pktout;
	cur_pktio = &thr_args->pktio[pktio];

	odp_barrier_wait(&barrier);

	/* Loop packets */
	while (!exit_threads) {
		int sent;
		unsigned tx_drops;

		if (num_pktio > 1) {
			dst_idx   = thr_args->pktio[pktio].tx_idx;
			pktin     = thr_args->pktio[pktio].pktin;
			pktout    = thr_args->pktio[pktio].pktout;
			cur_pktio = &thr_args->pktio[pktio];
			pktio++;
			if (pktio == num_pktio)
				pktio = 0;
		}

		pkts = odp_pktin_recv(pktin, pkt_tbl, MAX_PKT_BURST);
		if (odp_unlikely(pkts <= 0))
			continue;

		if (gbl_args->appl.error_check) {
			int rx_drops;

			/* Drop packets with errors */
			rx_drops = drop_err_pkts(pkt_tbl, pkts);

			if (odp_unlikely(rx_drops)) {
				stats->s.rx_drops += rx_drops;
				if (pkts == rx_drops)
					continue;

				pkts -= rx_drops;
			}
		}

		sent = process_pkt(pkt_tbl, pkts, cur_pktio);
		sent     = odp_unlikely(sent < 0) ? 0 : sent;
		tx_drops = pkts - sent;

		if (odp_unlikely(tx_drops)) {
			int i;

			stats->s.tx_drops += tx_drops;

#if 0
			/* Drop rejected packets */
			for (i = sent; i < pkts; i++)
				odp_packet_free(pkt_tbl[i]);
#endif
		}

		stats->s.packets += pkts;
	}

	/* Make sure that latest stat writes are visible to other threads */
	odp_mb_full();

	return 0;
}

/**
 * Create a pktio handle, optionally associating a default input queue.
 *
 * @param dev   Name of device to open
 * @param index Pktio index
 * @param pool  Pool to associate with device for packet RX/TX
 *
 * @retval 0 on success
 * @retval -1 on failure
 */
static int create_pktio(const char *dev, int idx, int num_rx, int num_tx,
			odp_pool_t pool)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	odp_pktio_capability_t capa;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	odp_pktio_op_mode_t mode_rx;
	odp_pktio_op_mode_t mode_tx;
	int num_tx_shared;

	odp_pktio_param_init(&pktio_param);

	pktio = odp_pktio_open(dev, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		printf("Error: failed to open %s\n", dev);
		return -1;
	}

	printf("created pktio %" PRIu64 " (%s)\n",
	       odp_pktio_to_u64(pktio), dev);

	if (odp_pktio_capability(pktio, &capa)) {
		printf("Error: capability query failed %s\n", dev);
		return -1;
	}

	odp_pktin_queue_param_init(&pktin_param);
	odp_pktout_queue_param_init(&pktout_param);

	num_tx_shared = capa.max_output_queues;
	mode_tx = ODP_PKTIO_OP_MT_UNSAFE;
	mode_rx = ODP_PKTIO_OP_MT_UNSAFE;

	if (num_rx > (int)capa.max_input_queues) {
		printf("Sharing %i input queues between %i workers\n",
		       capa.max_input_queues, num_rx);
		num_rx  = capa.max_input_queues;
		mode_rx = ODP_PKTIO_OP_MT;
	}

	if (num_tx > (int)capa.max_output_queues) {
		printf("Sharing %i output queues between %i workers\n",
		       num_tx_shared, num_tx);
		num_tx  = num_tx_shared;
		mode_tx = ODP_PKTIO_OP_MT;
	}

	pktin_param.hash_enable = 1;
	pktin_param.hash_proto.proto.ipv4_udp = 1;
	pktin_param.num_queues  = num_rx;
	pktin_param.op_mode     = mode_rx;

	pktout_param.op_mode    = mode_tx;
	pktout_param.num_queues = num_tx;

	if (odp_pktin_queue_config(pktio, &pktin_param)) {
		printf("Error: input queue config failed %s\n", dev);
		return -1;
	}

	if (odp_pktout_queue_config(pktio, &pktout_param)) {
		printf("Error: output queue config failed %s\n", dev);
		return -1;
	}

	if (odp_pktin_queue(pktio, gbl_args->pktios[idx].pktin,
			    num_rx) != num_rx) {
		printf("Error: pktin queue query failed %s\n",
		       dev);
		return -1;
	}

	if (odp_pktout_queue(pktio,
			     gbl_args->pktios[idx].pktout,
			     num_tx) != num_tx) {
		printf("Error: pktout queue query failed %s\n", dev);
		return -1;
	}

	printf("created %i input and %i output queues on (%s)\n",
	       num_rx, num_tx, dev);

	gbl_args->pktios[idx].num_rx_queue = num_rx;
	gbl_args->pktios[idx].num_tx_queue = num_tx;
	gbl_args->pktios[idx].pktio        = pktio;

	return 0;
}

/**
 *  Print statistics
 *
 * @param num_workers Number of worker threads
 * @param thr_stats Pointer to stats storage
 * @param duration Number of seconds to loop in
 * @param timeout Number of seconds for stats calculation
 *
 */
static int print_speed_stats(int num_workers, stats_t *thr_stats,
			     int duration, int timeout)
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
			pkts += thr_stats[i].s.packets;
			rx_drops += thr_stats[i].s.rx_drops;
			tx_drops += thr_stats[i].s.tx_drops;
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
	} while (loop_forever || (elapsed < duration));

	if (stats_enabled)
		printf("TEST RESULT: %" PRIu64 " maximum packets per second.\n",
		       maximum_pps);

	return pkts > 100 ? 0 : -1;
}

static void print_port_mapping(void)
{
	int if_count, num_workers;
	int thr, pktio;

	if_count    = gbl_args->appl.if_count;
	num_workers = gbl_args->appl.num_workers;

	printf("\nWorker mapping table (port[queue])\n--------------------\n");

	for (thr = 0; thr < num_workers; thr++) {
		int rx_idx, tx_idx;
		int rx_queue_idx, tx_queue_idx;
		thread_args_t *thr_args = &gbl_args->thread[thr];
		int num = thr_args->num_pktio;

		printf("Worker %i\n", thr);

		for (pktio = 0; pktio < num; pktio++) {
			rx_idx = thr_args->pktio[pktio].rx_idx;
			tx_idx = thr_args->pktio[pktio].tx_idx;
			rx_queue_idx = thr_args->pktio[pktio].rx_queue_idx;
			tx_queue_idx = thr_args->pktio[pktio].tx_queue_idx;
			printf("  %i[%i] ->  %i[%i]\n",
			       rx_idx, rx_queue_idx, tx_idx, tx_queue_idx);
		}
	}

	printf("\nPort config\n--------------------\n");

	for (pktio = 0; pktio < if_count; pktio++) {
		const char *dev = gbl_args->appl.if_names[pktio];

		printf("Port %i (%s)\n", pktio, dev);
		printf("  rx workers %i\n",
		       gbl_args->pktios[pktio].num_rx_thr);
		printf("  tx workers %i\n",
		       gbl_args->pktios[pktio].num_tx_thr);
		printf("  rx queues %i\n",
		       gbl_args->pktios[pktio].num_rx_queue);
		printf("  tx queues %i\n",
		       gbl_args->pktios[pktio].num_tx_queue);
	}

	printf("\n");
}

/**
 * Find the destination port for a given input port
 *
 * @param port  Input port index
 */
static int find_dest_port(int port)
{
	if (!gbl_args->appl.dsa_mode) {
		/* Even number of ports */
		if (gbl_args->appl.if_count % 2 == 0)
			return (port % 2 == 0) ? port + 1 : port - 1;

		/* Odd number of ports */
		if (port == gbl_args->appl.if_count - 1)
			return 0;
		else
			return port + 1;
	} else {
		return port;
	}
}

/*
 * Bind worker threads to interfaces and calculate number of queues needed
 *
 * less workers (N) than interfaces (M)
 *  - assign each worker to process every Nth interface
 *  - workers process inequal number of interfaces, when M is not divisible by N
 *  - needs only single queue per interface
 * otherwise
 *  - assign an interface to every Mth worker
 *  - interfaces are processed by inequal number of workers, when N is not
 *    divisible by M
 *  - tries to configure a queue per worker per interface
 *  - shares queues, if interface capability does not allows a queue per worker
 */
static void bind_workers(void)
{
	int if_count, num_workers;
	int rx_idx, tx_idx, thr, pktio;
	thread_args_t *thr_args;

	if_count    = gbl_args->appl.if_count;
	num_workers = gbl_args->appl.num_workers;

	/* initialize port forwarding table */
	for (rx_idx = 0; rx_idx < if_count; rx_idx++)
		gbl_args->dst_port[rx_idx] = find_dest_port(rx_idx);

#if 0
	for (thr = 0; thr < num_workers; thr++) {
		thr_args = &gbl_args->thread[thr];
		pktio    = thr_args->num_pktio;

		for (rx_idx = 0; rx_idx < if_count; rx_idx++) {
			tx_idx   = gbl_args->dst_port[rx_idx];
			thr_args->pktio[pktio].rx_idx = rx_idx;
			thr_args->pktio[pktio].tx_idx = tx_idx;
			thr_args->num_pktio++;
			pktio    = thr_args->num_pktio;

			gbl_args->pktios[rx_idx].num_rx_thr++;
			gbl_args->pktios[tx_idx].num_tx_thr++;
		}
	}
#else
	if (if_count > num_workers) {
		thr = 0;

		for (rx_idx = 0; rx_idx < if_count; rx_idx++) {
			thr_args = &gbl_args->thread[thr];
			pktio    = thr_args->num_pktio;
			tx_idx   = gbl_args->dst_port[rx_idx];
			thr_args->pktio[pktio].rx_idx = rx_idx;
			thr_args->pktio[pktio].tx_idx = tx_idx;
			thr_args->num_pktio++;

			gbl_args->pktios[rx_idx].num_rx_thr++;
			gbl_args->pktios[tx_idx].num_tx_thr++;

			thr++;
			if (thr >= num_workers)
				thr = 0;
		}
	} else {
		rx_idx = 0;

		for (thr = 0; thr < num_workers; thr++) {
			thr_args = &gbl_args->thread[thr];
			pktio    = thr_args->num_pktio;
			tx_idx   = gbl_args->dst_port[rx_idx];
			thr_args->pktio[pktio].rx_idx = rx_idx;
			thr_args->pktio[pktio].tx_idx = tx_idx;
			thr_args->num_pktio++;

			gbl_args->pktios[rx_idx].num_rx_thr++;
			gbl_args->pktios[tx_idx].num_tx_thr++;

			rx_idx++;
			if (rx_idx >= if_count)
				rx_idx = 0;
		}
	}
#endif
}

/*
 * Bind queues to threads and fill in missing thread arguments (handles)
 */
static void bind_queues(void)
{
	int num_workers;
	int thr, pktio;

	num_workers = gbl_args->appl.num_workers;

	for (thr = 0; thr < num_workers; thr++) {
		int rx_idx, tx_idx;
		thread_args_t *thr_args = &gbl_args->thread[thr];
		int num = thr_args->num_pktio;

		for (pktio = 0; pktio < num; pktio++) {
			int rx_queue, tx_queue;

			rx_idx   = thr_args->pktio[pktio].rx_idx;
			tx_idx   = thr_args->pktio[pktio].tx_idx;
			rx_queue = gbl_args->pktios[rx_idx].next_rx_queue;
			tx_queue = gbl_args->pktios[tx_idx].next_tx_queue;

			thr_args->pktio[pktio].rx_queue_idx = rx_queue;
			thr_args->pktio[pktio].tx_queue_idx = tx_queue;
			thr_args->pktio[pktio].pktin =
				gbl_args->pktios[rx_idx].pktin[rx_queue];
			thr_args->pktio[pktio].pktout =
				gbl_args->pktios[tx_idx].pktout[tx_queue];
			thr_args->pktio[pktio].rx_queue =
				gbl_args->pktios[rx_idx].rx_q[rx_queue];
			thr_args->pktio[pktio].tx_queue =
				gbl_args->pktios[tx_idx].tx_q[tx_queue];
			thr_args->pktio[pktio].rx_pktio =
				gbl_args->pktios[rx_idx].pktio;
			thr_args->pktio[pktio].tx_pktio =
				gbl_args->pktios[tx_idx].pktio;

			rx_queue++;
			tx_queue++;

			if (rx_queue >= gbl_args->pktios[rx_idx].num_rx_queue)
				rx_queue = 0;
			if (tx_queue >= gbl_args->pktios[tx_idx].num_tx_queue)
				tx_queue = 0;

			gbl_args->pktios[rx_idx].next_rx_queue = rx_queue;
			gbl_args->pktios[tx_idx].next_tx_queue = tx_queue;
		}
	}
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "OpenDataPlane NAT application.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth0,eth1 -d 192.168.0.0/24/10.0.0.1/32 -d 192.168.1.0/24/10.0.1.1/32\n"
		   "       %s -i eth0,eth1 -d 192.168.0.0/24/10.0.0.1/24 -d 192.168.1.0/24/10.0.1.0/24\n"
		   " eth0(the first one) is WAN interface, others are LAN interfaces\n"
		   " Pkts from WAN interface do DNAT, from LAN interface do SNAT\n"
	       " In the above example 1,\n"
	       " Local subnet 192.168.0.0/24 is translated to public IP 10.0.0.1\n"
	       " Local subnet 192.168.1.0/24 is translated to public IP 10.0.1.1\n"
	       " In the above example 2,\n"
	       " Local subnet 192.168.0.0/24 is translated to public IP 10.0.0.x, x is the last byte of old IP\n"
	       " Local subnet 192.168.1.0/24 is translated to public IP 10.0.1.x, x is the last byte of old IP\n"
	       "\n"
		   "DSA Mode\n"
		   "  E.g. %s -i eth0,eth1 -d 192.168.0.0/24/10.0.0.1/32 -d 192.168.1.0/24/10.0.1.1/32 -l 100 -w 200 -s\n"
		   "DSA OPTIONS:\n"
		   "  -s,	Enable DSA mode\n"
		   "  100 is LAN VID inside DSA tag, 200 is WAN VID inside DSA tag\n"
		   "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "                  Interface count min 1, max %i\n"
	       "  -d, --address   Local IP and public IP mapping\n"
	       "\n"
	       "Optional OPTIONS:\n"
		   "  -s, --dsa DSA tag mode\n"
           "  -l, --lan_vid <vid> DSA tag mode, LAN VID\n"
           "  -w, --wan_Vid VIDs(comma-separated, no spaces) DSA tag mode, WAN VIDs\n"
	       "  -o, --aging time of DNAT entries in seconds (default is 300 seconds).\n"
	       "  -c, --count <number> CPU count.\n"
	       "  -a, --accuracy <number> Time in seconds get print statistics\n"
	       "                          (default is 1 second).\n"
	       "  -g, --debug debug mode\n"
	       "  -h, --help           Display help and exit.\n\n"
	       "\n", NO_PATH(progname), NO_PATH(progname), NO_PATH(progname), NO_PATH(progname), MAX_PKTIOS
	    );
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
	char *addr_str, *addr_str2, *mask_str, *tap_str;
	size_t len;
	int i;
	static const struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"time", required_argument, NULL, 't'},
		{"accuracy", required_argument, NULL, 'a'},
		{"interface", required_argument, NULL, 'i'},
		{"address", required_argument, NULL, 'd'},
		{"aging", required_argument, NULL, 'o'},
		{"lan_vid", required_argument, NULL, 'l'},
		{"wan_vid", required_argument, NULL, 'w'},
		{"dsa", no_argument, NULL, 's'},
		{"debug", no_argument, NULL, 'g'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts =  "+c:+a:i:d:o:l:w:shg";

	/* let helper collect its own arguments (e.g. --odph_proc) */
	odph_parse_options(argc, argv, shortopts, longopts);

	appl_args->time = 0; /* loop forever if time to run is 0 */
	appl_args->accuracy = 1; /* get and print pps stats second */
	appl_args->error_check = 0; /* don't check packet errors by default */
	appl_args->dsa_mode = 0;

	opterr = 0; /* do not issue errors on helper options */
	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->cpu_count = atoi(optarg);
			break;
		case 'a':
			appl_args->accuracy = atoi(optarg);
			break;
		case 'i':
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
			for (token = strtok(optarg, ","), i = 0;
			     (token != NULL) && (i < ODP_NAT_MAX_ETH_IF);
			     token = strtok(NULL, ","), i++)
				;

			appl_args->if_phy_count = i;
			if (appl_args->if_phy_count < 1 ||
			    appl_args->if_phy_count > MAX_PKTIOS) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			appl_args->if_count = appl_args->if_phy_count;
			break;
		case 'd':
		{
			uint32_t local_subnet, local_mask;
			uint32_t public_subnet, public_mask;

			addr_str = strtok(optarg, "/");
			if (addr_str == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			mask_str = strtok(NULL, "/");
			if (mask_str == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			local_mask = ((1u << atoi(mask_str)) - 1) << (32 - atoi(mask_str));
			addr_str2 = strtok(NULL, "/");
			if (addr_str == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			mask_str = strtok(NULL, "/");
			if (mask_str == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			public_mask = ((1ull << atoi(mask_str)) - 1) << (32 - atoi(mask_str));

			local_subnet = ipv4_aton(addr_str);
			public_subnet = ipv4_aton(addr_str2);
			ip_table_add_entry(local_subnet, local_mask, public_subnet, public_mask);
			break;
		}

		case 'o':
			appl_args->aging_time = atoi(optarg);
			break;

		case 's':
			appl_args->dsa_mode = 1;
			break;

		case 'l':
			appl_args->lan_vid = atoi(optarg);
			break;

        case 'w':
            len = strlen(optarg);
            if (len == 0) {
                    usage(argv[0]);
                    exit(EXIT_FAILURE);
            }
            len += 1;   /* add room for '\0' */

            appl_args->if_wan_str = malloc(len);
            if (appl_args->if_wan_str == NULL) {
                    usage(argv[0]);
                    exit(EXIT_FAILURE);
            }

            /* store the if wan names (reset names string) */
            strcpy(appl_args->if_wan_str, optarg);
            tap_str = appl_args->tap_str;

            sprintf(tap_str, "tap:lan");
            tap_str += strlen(tap_str);

            for (token = strtok(optarg, ","), i = 0;
                (token != NULL) && (i < ODP_NAT_MAX_WAN_IP); token = strtok(NULL, ","), i++) {
                appl_args->wan_vid[i] = atoi(token);
                sprintf(tap_str, ",tap:wan%d", appl_args->wan_vid[i]);
                tap_str += strlen(tap_str);
            }
            appl_args->if_wan_count = i;
            break;

		case 'g':
			appl_args->debug_mode = 1;
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

    /* allocate storage for the if names */
    appl_args->if_count = appl_args->if_phy_count + appl_args->if_wan_count + (appl_args->dsa_mode ? 1 : 0); // 1 is LAN TAP

    appl_args->if_names = calloc(appl_args->if_count, sizeof(char *));
    /* store the if names (reset names string) */
    for (token = strtok(appl_args->if_str, ","), i = 0;
         (token != NULL) && (i < ODP_NAT_MAX_ETH_IF); token = strtok(NULL, ","), i++) {
        appl_args->if_names[i] = token;
    }

    if (appl_args->dsa_mode) {
        /* TAP interface names */
        for (token = strtok(appl_args->tap_str, ",");
             (token != NULL) && (i < ODP_NAT_MAX_WAN_IP); token = strtok(NULL, ","), i++) {
            appl_args->if_names[i] = token;
        }
	}

    appl_args->src_dev_id = ODP_NAT_DEF_DEV_ID;

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
	       "ODP impl name:   %s\n"
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
	       "IF-count:        %i\n"
	       "Using IFs:      ",
	       progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
    printf("\n");
    printf("Debug Mode %s\n", appl_args->debug_mode ? "Enabled" : "Disabled");
    printf("DSA Mode %s\n", appl_args->dsa_mode ? "Enabled" : "Disabled");
    if (appl_args->dsa_mode) {
        printf ("LAN VID: %d\n", appl_args->lan_vid);
        printf ("Number of WANs: %d\n", appl_args->if_wan_count);
        printf ("WAN VIDs: ");
        for (i = 0; i < appl_args->if_wan_count; ++i)
            printf("%d ", appl_args->wan_vid[i]);
        printf("\n");
    }


	printf("\n\n");
	fflush(NULL);
}

static void gbl_args_init(args_t *args)
{
	int pktio, queue;

	memset(args, 0, sizeof(args_t));

	for (pktio = 0; pktio < MAX_PKTIOS; pktio++) {
		args->pktios[pktio].pktio = ODP_PKTIO_INVALID;

		for (queue = 0; queue < MAX_QUEUES; queue++)
			args->pktios[pktio].rx_q[queue] = ODP_QUEUE_INVALID;
	}
	args->appl.aging_time = 300;

	odp_rwlock_init(&args->snat_lock);
	odp_rwlock_init(&args->dnat_lock);
}

/**
 * ODP NAT main function
 */
int main(int argc, char *argv[])
{
	odph_odpthread_t thread_tbl[MAX_WORKERS];
	odp_pool_t pool;
	int i;
	int cpu;
	int num_workers;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	int ret;
	stats_t *stats;
	int if_count;
	odp_instance_t instance;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		printf("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		printf("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t),
			      ODP_CACHE_LINE_SIZE, 0);

	gbl_args = odp_shm_addr(shm);

	if (gbl_args == NULL) {
		printf("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	gbl_args_init(gbl_args);

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &gbl_args->appl);

	/* Default to system CPU count unless user specified */
	num_workers = MAX_WORKERS;
	if (gbl_args->appl.cpu_count)
		num_workers = gbl_args->appl.cpu_count;

	//WA: don't reserve CPU for control plan and Linux
	odp_cpumask_zero(&odp_global_data.worker_cpus);
	odp_cpumask_zero(&odp_global_data.control_cpus);
	odp_cpumask_set(&odp_global_data.control_cpus, 0);
	for (i = 0; i < odp_global_data.num_cpus_installed; i++) {
		odp_cpumask_set(&odp_global_data.worker_cpus, i);
	}

	/* Get default worker cpumask */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	gbl_args->appl.num_workers = num_workers;

	for (i = 0; i < num_workers; i++)
		gbl_args->thread[i].thr_idx    = i;

	if_count = gbl_args->appl.if_count;

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet pool", &params);

	if (pool == ODP_POOL_INVALID) {
		printf("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	bind_workers();

	for (i = 0; i < if_count; ++i) {
		const char *dev = gbl_args->appl.if_names[i];
		int num_rx, num_tx;

		num_rx = gbl_args->pktios[i].num_rx_thr;
		num_tx = gbl_args->pktios[i].num_tx_thr;

		if (create_pktio(dev, i, num_rx, num_tx, pool))
			exit(EXIT_FAILURE);
	}

	gbl_args->pktios[i].pktio = ODP_PKTIO_INVALID;

	bind_queues();

	print_port_mapping();

	memset(thread_tbl, 0, sizeof(thread_tbl));

	stats = gbl_args->stats;

	odp_barrier_init(&barrier, num_workers + 1);

	/* Create worker threads */
	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < num_workers; ++i) {
		odp_cpumask_t thd_mask;
		odph_odpthread_params_t thr_params;

		memset(&thr_params, 0, sizeof(thr_params));
		thr_params.start    = run_worker;
		thr_params.arg      = &gbl_args->thread[i];
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = instance;

		gbl_args->thread[i].stats = &stats[i];

		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, cpu);
		odph_odpthreads_create(&thread_tbl[i], &thd_mask,
				       &thr_params);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	/* Start packet receive and transmit */
	for (i = 0; i < if_count; ++i) {
		odp_pktio_t pktio;

		pktio = gbl_args->pktios[i].pktio;
		ret   = odp_pktio_start(pktio);
		if (ret) {
			printf("Error: unable to start %s\n",
			       gbl_args->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}
	}

	ret = print_speed_stats(num_workers, stats, gbl_args->appl.time,
				gbl_args->appl.accuracy);

	exit_threads = 1;

	/* Master thread waits for other threads to exit */
	for (i = 0; i < num_workers; ++i)
		odph_odpthreads_join(&thread_tbl[i]);

	free(gbl_args->appl.if_names);
	free(gbl_args->appl.if_str);
	free(gbl_args->appl.if_wan_str);

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

	printf("Exit %d\n\n", ret);
	return ret;
}
