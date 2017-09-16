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
#include <signal.h>
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
#define MAX_WORKERS            4

/** @def SHM_PKT_POOL_SIZE
 * @brief Size of the shared memory block
 */
#define SHM_PKT_POOL_SIZE      1280

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
#define INVALID_VID		0xFFFF

#define MAX_STRING		32

#define DEFAULT_AGING_TIME	300
#define MAX_AGING_TIME		3600

#define MV_DSA_MODE_BIT		(0x1ULL << 62)
#define MV_EXT_DSA_MODE_BIT	(0x1ULL << 63)

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

typedef enum {
	HASH_PRIM_LOCATION,
	HASH_SEC_LOCATION,
} odph_hash_location_e;

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

	uint32_t aging_time;	/* NAT entries aging time */
	int dsa_mode;
	int debug_mode;
	int print_table;
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
	uint8_t pad1;
	uint16_t pad2;
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
	ipv4_5tuple_t 	ipv4_5tuple;
	uint32_t	hash_value;
	uint8_t		hash_location;
	uint8_t		valid;
	uint16_t     	target_port; 	/* For SNAT, it is source port, for DNAT, it is dest port */
	uint32_t     	target_ip; 	/* For SNAT, it is source ip, for DNAT, it is dest ip */
	struct nat_entry_t *reverse_nat_entry;
	uint32_t	counter;
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
	uint8_t word1_byte3;
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
static int glb_stop;

/** Global pointer to args */
static args_t *gbl_args;
/** Global barrier to synchronize main and workers */
static odp_barrier_t barrier;

static odp_pool_t gbl_tap_pool;

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

static uint32_t swap32(uint32_t value)
{
	return	((value << 24) & 0xff000000) |
		((value <<  8) & 0x00ff0000) |
		((value >>  8) & 0x0000ff00) |
		((value >> 24) & 0x000000ff);
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
	if (odp_likely(pool->head != NULL)) {
		pool->head = pool->head->next;
		if (odp_likely(pool->head != NULL))
			pool->head->prev = NULL;
	}
	odp_rwlock_write_unlock(&pool->lock);

	if (odp_likely(ptr != NULL))
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

	for (k = 0; k < IP_MAP_TBL_SIZE; k++) {
		iptbl = &gbl_args->ip_map_tbl[k];
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
			if (odp_unlikely(gbl_args->appl.debug_mode)) {
				printf("ip_table_add_entry: ");
				printf("%32s %32s %32s %32s -> %d\n",
				       ipv4_str(subnet_str, &subnet),
				       ipv4_str(mask_str, &mask),
				       ipv4_str(pub_subnet_str, &public_subnet),
				       ipv4_str(pub_mask_str, &public_mask), k);
		       }
			break;
		}
	}
}

static void *odp_nat_packet_l3_ptr(odp_packet_t pkt, uint32_t *offset, uint16_t *ethtype)
{
	odph_ethhdr_t *eth;
	odph_vlanhdr_t *vlan;
	uint8_t *parseptr;

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
		odp_packet_l3_offset_set(pkt, *offset);
		return odp_packet_offset(pkt, *offset, NULL, NULL);
	}
	return NULL;
}

static void *odp_nat_packet_l4_ptr(odp_packet_t pkt, void *l3_hdr, uint32_t l3_offset, uint16_t ethtype)
{
	uint32_t l4_offset;

	if (ethtype == ODPH_ETHTYPE_IPV4) {
		odph_ipv4hdr_t *ipv4hdr = (odph_ipv4hdr_t *)l3_hdr;
		uint8_t ihl = ODPH_IPV4HDR_IHL(ipv4hdr->ver_ihl);

		l4_offset = l3_offset + (ihl << 2);
		odp_packet_l4_offset_set(pkt, l4_offset);
		return (odph_ipv4hdr_t *)odp_packet_offset(pkt, l4_offset, NULL, NULL);
	}
	return NULL;
}

static inline int strip_dsa_hdr(odp_packet_t pkt)
{
	odph_ethaddr_t macaddr[2];

	if (odp_packet_copy_to_mem(pkt, 0, 2 * sizeof(odph_ethaddr_t),
				   &macaddr) != 0)
		return 1;

	odp_packet_pull_head(pkt, sizeof(odph_dsa_t));

	if (odp_packet_copy_from_mem(pkt, 0, 2 * sizeof(odph_ethaddr_t),
				     &macaddr) != 0) {
		return 1;
	}

	return 0;
}

static int process_tocpu_lan(odp_packet_t pkt, int strip_dsa)
{
    odp_nat_pktio_t pktio;
    int tx_idx;

    tx_idx = gbl_args->appl.if_phy_count;

    pktio.tx_idx = tx_idx;
    pktio.pktout = gbl_args->pktios[tx_idx].pktout[0];
    pktio.tx_queue = gbl_args->pktios[tx_idx].tx_q[0];
    pktio.tx_pktio = gbl_args->pktios[tx_idx].pktio;

	if (strip_dsa == 1) {
		if (odp_unlikely((strip_dsa_hdr(pkt) == 1)))
			return 1;
	}

    if (odp_unlikely(gbl_args->appl.debug_mode)) {
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

static int process_tocpu_wan(odp_packet_t pkt, int strip_dsa)
{
    odp_nat_pktio_t pktio;
	int tx_idx = 0;
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

	if (strip_dsa == 1) {
		if (odp_unlikely((strip_dsa_hdr(pkt) == 1)))
			return 1;
	}

    if (odp_unlikely(gbl_args->appl.debug_mode)) {
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
    /* bit[31,30]:11 (forward), bit[28:24]:01000 (src_dev) */
    dsaFill.src_dev = 0xC0;
    dsaFill.src_dev |= gbl_args->appl.src_dev_id & DEV_ID_MASK;
    /* bit[23,19]:63(src_port) */
    dsaFill.src_port = DSA_SRC_PORT_CPU << 3;
    dsaFill.word1_byte3 = 0x20;
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

    if (odp_unlikely(gbl_args->appl.debug_mode)) {
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
    /* bit[31,30]:11 (forward), bit[28:24]:01000 (src_dev) */
    dsaFill.src_dev = 0xC0;
    dsaFill.src_dev |= gbl_args->appl.src_dev_id & DEV_ID_MASK;
    /* bit[23,19]:63(src_port) */
    dsaFill.src_port = DSA_SRC_PORT_CPU << 3;
    dsaFill.word1_byte3 = 0x20;
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

    if (odp_unlikely(gbl_args->appl.debug_mode)) {
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

/*
static int unknown_pkt_to_cpu(odp_packet_t pkt)
{
	odph_dsa_ethhdr_t *eth;

	eth = (odph_dsa_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
	if ((eth->dsa.src_port & 0x7) == (DEFAULT_CPU_CODE >> 1))
		return 1;
	return 0;
}
*/

/**
 * Find entry in hash bucket list
 *
 * @param tbl		Hash Table
 * @param ipv4_5tuple	5-tuple structure
 * @param hash_value    5-tuple hash value
 * @param location	primary or secondary hash location
 *
 * @return pointer to the entry or NULL
 */
static inline nat_entry_t *bucket_search(nat_entry_t tbl[][NAT_TBL_DEPTH],
					 ipv4_5tuple_t *ipv4_5tuple,
					 uint32_t hash_value,
					 int location)
{
	int j;
	uint32_t hash_idx = hash_value & (NAT_TBL_SIZE - 1);

	if (odp_unlikely(location == HASH_SEC_LOCATION))
		hash_idx = swap32(hash_value) & (NAT_TBL_SIZE - 1);

	for (j = 0; j < NAT_TBL_DEPTH; j++) {
		if (odp_unlikely((!tbl[hash_idx][j].valid)))
			continue;

		if (tbl[hash_idx][j].hash_value == hash_value) {
			if (0 == memcmp((void *)ipv4_5tuple,
					&tbl[hash_idx][j].ipv4_5tuple,
					sizeof(ipv4_5tuple_t) -
					sizeof(uint32_t))) {
				return &tbl[hash_idx][j];
			}
		}
	}

	return NULL;
}

/**
 * Find entry in hash table
 *
 * @param tbl		Hash Table
 * @param hash_value    32 bit hash key value
 * @param ipv4_5tuple	5-tuple structure
 *
 * @return pointer to the entry or NULL
 */
static inline nat_entry_t *find_hash_entry(nat_entry_t tbl[][NAT_TBL_DEPTH],
					   uint32_t hash_value,
					   ipv4_5tuple_t *ipv4_5tuple)
{
	nat_entry_t *hash_entry;

	/* search entry in the primary location */
	hash_entry = bucket_search(tbl, ipv4_5tuple, hash_value,
				   HASH_PRIM_LOCATION);
	if (odp_unlikely(NULL == hash_entry))
		/* search entry in the secondary location */
		return bucket_search(tbl, ipv4_5tuple, hash_value,
				     HASH_SEC_LOCATION);
	else
		return hash_entry;
}

/**
 * Add entry to hash table
 *
 * The function is not thread safe and doesn't check the existense of the entry.
 * It is a responsibily of the application to call for the function inside a
 * critical region and check the existense of the entry before the call.
 *
 * @param tbl		Hash Table
 * @param hash_value    32 bit hash key value
 * @param entry		NAT entry
 *
 * @return		pointer to added entry or NULL for error
 */
static inline nat_entry_t *add_hash_entry(nat_entry_t tbl[][NAT_TBL_DEPTH],
					  uint32_t hash_value,
					  nat_entry_t *entry)
{
	int i, j;
	uint32_t hash_idx, new_index;

	hash_idx = hash_value & (NAT_TBL_SIZE - 1);

	entry->hash_value = hash_value;
	entry->hash_location = HASH_PRIM_LOCATION;
	entry->counter = 0;
	entry->valid = 1;

	/* search for empty place in the primary location */
	for (i = 0; i < NAT_TBL_DEPTH; i++) {
		if (odp_unlikely((!tbl[hash_idx][i].valid))) {
			/* found empty slot, add entry */
			memcpy((void *)&tbl[hash_idx][i], (void *)entry,
			       sizeof(nat_entry_t));
			return &tbl[hash_idx][i];
		}
	}

	/* place not found, move one of the entries to the secondary location */
	for (i = NAT_TBL_DEPTH - 1; i >= 0; i--) {
		if (odp_unlikely(tbl[hash_idx][i].hash_location ==
		    HASH_SEC_LOCATION))
			continue;

		/* calculate secondary index of the candidate */
		new_index = swap32(tbl[hash_idx][i].hash_value) &
			(NAT_TBL_SIZE - 1);
		for (j = 0; j < NAT_TBL_DEPTH; j++) {
			if (tbl[new_index][j].valid)
				continue;
			/* found empty position, move entry */
			tbl[hash_idx][i].hash_location = HASH_SEC_LOCATION;
			memcpy((void *)&tbl[new_index][j],
			       (void *)&tbl[hash_idx][i], sizeof(nat_entry_t));
			/* update the pointer of the reversed entry */
			tbl[new_index][j].reverse_nat_entry->reverse_nat_entry =
				&tbl[new_index][j];
			/* place the new entry */
			memcpy((void *)&tbl[hash_idx][i], (void *)entry,
			       sizeof(nat_entry_t));
			return &tbl[hash_idx][i];
		}
	}

	printf("add_hash_entry: failed to add entry\n");
	return NULL;
}

static inline int build_hash_search_key(ipv4_5tuple_t *tuple,
					odph_ipv4hdr_t *ipv4hdr,
					odph_udphdr_t *udphdr)
{
	odph_icmphdr_t *icmphdr = (odph_icmphdr_t *)udphdr;

	tuple->src_ip = ntohl(ipv4hdr->src_addr);
	tuple->dst_ip = ntohl(ipv4hdr->dst_addr);
	tuple->protocol = ipv4hdr->proto;
	tuple->pad1 = 0;
	tuple->pad2 = 0;
	if (odp_likely(tuple->protocol != ODPH_IPPROTO_ICMPv4)) {
		tuple->src_port = ntohs(udphdr->src_port);
		tuple->dst_port = ntohs(udphdr->dst_port);
	} else {
		if ((icmphdr->type != 8) &&  (icmphdr->type != 0))
			return 1;
		if (icmphdr->code)
			return 1;
		tuple->src_port = ntohs(icmphdr->un.echo.id);
		tuple->dst_port = 0;
	}
	return 0;
}

static inline void snat_dsa_processing(odp_packet_t pkt)
{
	odph_dsa_ethhdr_t *eth;
	unsigned char src_dev_id, dst_dev_id;

	eth = (odph_dsa_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
	/* swap Source and Dest DevID of DSA tag */
	src_dev_id = eth->dsa.src_dev & DEV_ID_MASK;
	dst_dev_id = eth->dsa.dst_dev & DEV_ID_MASK;
	eth->dsa.src_dev &= 0xE0;
	eth->dsa.dst_dev &= 0xE0;
	eth->dsa.src_dev |= dst_dev_id;
	eth->dsa.dst_dev |= src_dev_id;
}

static inline int add_dsa_snat_fromcpu(odp_packet_t pkt,
				       odp_nat_pktio_t *rx_pktio)
{
	odph_dsa_t   dsaFill;
	odph_ethaddr_t macaddr[2];
	uint8_t *data;
	int j;

	memset(&dsaFill, 0, sizeof(odph_dsa_t));
	/* bit[31,30]:11 (forward), bit[28:24]:01000 (src_dev) */
	dsaFill.src_dev = 0xC0;
	dsaFill.src_dev |= gbl_args->appl.src_dev_id & DEV_ID_MASK;
	/* bit[23,19]:63(src_port) */
	dsaFill.src_port = DSA_SRC_PORT_CPU << 3;
	dsaFill.word1_byte3 = 0x20;
	dsaFill.vid  = htons((1 << 12) |
		       gbl_args->appl.wan_vid[rx_pktio->rx_idx -
		       gbl_args->appl.if_phy_count - 1]);

	if (odp_packet_copy_to_mem(pkt, 0, 2 * sizeof(odph_ethaddr_t),
				   &macaddr) != 0) {
		return 1;
	}

	odp_packet_push_head(pkt, sizeof(odph_dsa_t));

	if (odp_packet_copy_from_mem(pkt, 0, 2 * sizeof(odph_ethaddr_t),
				     &macaddr) != 0) {
		return 1;
	}

	if (odp_packet_copy_from_mem(pkt, 2 * sizeof(odph_ethaddr_t),
				     sizeof(odph_dsa_t), &dsaFill) != 0) {
		return 1;
	}

	if (odp_unlikely(gbl_args->appl.debug_mode)) {
		data = (uint8_t *)odp_packet_l2_ptr(pkt, NULL);
		printf("Routed pkt from CPU.\n");

		for (j = 0; j < 64; j++)
			printf("%02x ", data[j]);
		printf("\n");
	}
	return 0;
}

static inline void do_snat(odph_ipv4hdr_t *ipv4hdr, odph_udphdr_t *udphdr,
			   uint32_t target_ip, uint16_t target_port,
			   uint8_t protocol)
{
	odph_icmphdr_t *icmphdr = (odph_icmphdr_t *)udphdr;
	odph_tcphdr_t  *tcphdr = (odph_tcphdr_t *)udphdr;
	/*
	if (odp_unlikely(gbl_args->appl.debug_mode))
		printf("Changing src address from %08x to %08x\n",
		       ipv4hdr->src_addr, htonl(target_ip));
	*/
	ipv4hdr->src_addr = ntohl(target_ip);
	ipv4hdr->chksum = 0;
	switch (protocol) {
	case ODPH_IPPROTO_UDP:
		udphdr->src_port = ntohs(target_port);
		udphdr->chksum = 0;
		break;
	case ODPH_IPPROTO_TCP:
		tcphdr->src_port = ntohs(target_port);
		tcphdr->cksm = 0;
		break;
	case ODPH_IPPROTO_ICMPv4:
		icmphdr->un.echo.id = ntohs(target_port);
		icmphdr->chksum = 0;
		icmphdr->chksum = ~net_cksum((uint8_t *)icmphdr,
					     (ntohs(ipv4hdr->tot_len) -
					     ODPH_IPV4HDR_LEN) >> 1);
		break;
	default:
		break;
	}
}

static inline void do_dnat(odph_ipv4hdr_t *ipv4hdr, odph_udphdr_t *udphdr,
			   uint32_t target_ip, uint16_t target_port,
			   uint8_t protocol)
{
	odph_icmphdr_t *icmphdr = (odph_icmphdr_t *)udphdr;
	odph_tcphdr_t  *tcphdr = (odph_tcphdr_t *)udphdr;
	/*
	if (odp_unlikely(gbl_args->appl.debug_mode))
		printf("Changing dst address from %08x to %08x\n",
		       ipv4hdr->dst_addr, htonl(target_ip));
	*/
	ipv4hdr->dst_addr = htonl(target_ip);
	ipv4hdr->chksum = 0;
	switch (protocol) {
	case ODPH_IPPROTO_UDP:
		udphdr->dst_port = htons(target_port);
		udphdr->chksum = 0;
		break;
	case ODPH_IPPROTO_TCP:
		tcphdr->dst_port = htons(target_port);
		tcphdr->cksm = 0;
		break;
	case ODPH_IPPROTO_ICMPv4:
		icmphdr->un.echo.id = htons(target_port);
		icmphdr->chksum = 0;
		icmphdr->chksum = ~net_cksum((uint8_t *)icmphdr,
					     (ntohs(ipv4hdr->tot_len) -
					     ODPH_IPV4HDR_LEN) >> 1);
		break;
	default:
		break;
	}
}

/**
 * Learn NAT entry
 *
 * @param snat_ipv4	SNAT 5-tuple
 * @param hash_value    32 bit hash key value
 * @param ipv4hdr	IP header pointer
 * @param udphdr	L4 header pointer
 *
 * @param ret_ptr	returned pointer to added entry
 * @return		process_pkt proceed value
 *			0: send (forward not added entry), 1: drop,
 *			4: successfully added entry, snat should be performed
 */
static inline int learn_nat_entry(ipv4_5tuple_t snat_ipv4, uint32_t hash_value,
				  odph_ipv4hdr_t *ipv4hdr,
				  odph_udphdr_t *udphdr, nat_entry_t **ret_ptr)
{
	uint32_t target_ip;
	ipv4_5tuple_t dnat_ipv4;
	nat_entry_t snat_entry, dnat_entry;
	nat_entry_t *snat_ptr, *dnat_ptr;
	uint32_t dnat_hash_value;
	odph_nat_wan_pool_t *port_pool = NULL;
	odph_nat_pool_t *nat_pool;

	/* Not found in SNAT table */
	/* 1. Search the IP mapping entry */
	target_ip = ip_table_lookup(snat_ipv4.src_ip);
	/* No match in IP table,probably control plane packet,drop it */
	if (odp_unlikely(!target_ip)) {
		if (odp_unlikely(gbl_args->appl.debug_mode)) {
			printf("not found in SNAT table. ");
			printf("target_ip doesn't exist\n");
		}
		return 1;
	}

	port_pool = ip_table_lookup_pool(snat_ipv4.src_ip);
	switch (snat_ipv4.protocol) {
	case ODPH_IPPROTO_UDP:
		nat_pool = &port_pool->udp_port_pool;
		break;
	case ODPH_IPPROTO_TCP:
		nat_pool = &port_pool->tcp_port_pool;
		break;
	case ODPH_IPPROTO_ICMPv4:
		nat_pool = &port_pool->icmp_id_pool;
		break;
	default:
		return 0;
	}

	/* prepare SNAT entry */
	snat_entry.ipv4_5tuple = snat_ipv4;
	snat_entry.target_ip = target_ip;
	odp_rwlock_write_lock(&gbl_args->snat_lock);
	/* verify under lock that the entry doesn't exist */
	snat_ptr = find_hash_entry(gbl_args->snat_tbl, hash_value, &snat_ipv4);
	if (NULL != snat_ptr) {
		odp_rwlock_write_unlock(&gbl_args->snat_lock);
		snat_ptr->counter = 0;
		*ret_ptr = snat_ptr;
		if (odp_likely(snat_ptr->target_ip)) {
			/* DO SNAT */
			return 4;
		}
		return 0;
	}

	/* allocate a port from the pool in order to modify a local
	 * source port */
	snat_entry.target_port = allocate_node_for_pool(nat_pool);
	if (odp_unlikely(snat_entry.target_port == 0)) {
		odp_rwlock_write_unlock(&gbl_args->snat_lock);
		return 1;
	}

	/* 2. Add to SNAT table */
	snat_ptr = add_hash_entry(gbl_args->snat_tbl, hash_value, &snat_entry);

	if (odp_unlikely(NULL == snat_ptr)) {
		release_node_for_pool(nat_pool, snat_entry.target_port);
		odp_rwlock_write_unlock(&gbl_args->snat_lock);

		if (odp_unlikely(gbl_args->appl.debug_mode)) {
			printf("Failed to add SNAT entry ");
			printf("%08x %d %08x %d %d\n", snat_ipv4.src_ip,
			       snat_ipv4.src_port, snat_ipv4.dst_ip,
			       snat_ipv4.dst_port, snat_ipv4.protocol);
		}
		return 1;
	}

	odp_rwlock_write_unlock(&gbl_args->snat_lock);
	*ret_ptr = snat_ptr;

	if (odp_unlikely(gbl_args->appl.debug_mode))
		printf("add to snat table: %08x %d %08x %d %d %08x\n",
		       snat_ipv4.src_ip, snat_ipv4.src_port,
		       snat_ipv4.dst_ip, snat_ipv4.dst_port,
		       snat_ipv4.protocol, snat_ptr->target_ip);

	/* 3. Add to DNAT table */
	if (odp_likely(snat_entry.target_ip)) {
		/* DNAT entry */
		dnat_ipv4.src_ip = snat_ipv4.dst_ip;
		dnat_ipv4.src_port = snat_ipv4.dst_port;
		dnat_ipv4.dst_port = snat_ptr->target_port;
		dnat_ipv4.protocol = snat_ipv4.protocol;
		dnat_ipv4.dst_ip = snat_ptr->target_ip;
		dnat_ipv4.pad1 = 0;
		dnat_ipv4.pad2 = 0;
		if (odp_unlikely(snat_ipv4.protocol == ODPH_IPPROTO_ICMPv4)) {
			dnat_ipv4.src_port = snat_entry.target_port;
			dnat_ipv4.dst_port = 0;
		}
		dnat_entry.ipv4_5tuple = dnat_ipv4;
		dnat_entry.target_ip = snat_ipv4.src_ip;
		dnat_entry.target_port = snat_ipv4.src_port;
		dnat_entry.reverse_nat_entry = snat_ptr;

		dnat_hash_value = XXH32((void *)&dnat_ipv4,
					sizeof(ipv4_5tuple_t), NAT_HASH_SEED);

		odp_rwlock_write_lock(&gbl_args->dnat_lock);
		dnat_ptr = add_hash_entry(gbl_args->dnat_tbl,
					  dnat_hash_value, &dnat_entry);
		odp_rwlock_write_unlock(&gbl_args->dnat_lock);

		if (odp_unlikely(NULL == dnat_ptr)) {
			if (odp_unlikely(gbl_args->appl.debug_mode)) {
				printf("Failed to add DNAT entry ");
				printf("%08x %d %08x %d %d\n",
				       dnat_ipv4.src_ip, dnat_ipv4.src_port,
				       dnat_ipv4.dst_ip, dnat_ipv4.dst_port,
				       dnat_ipv4.protocol);
			}
			return 1;
		}

		/* update snat reverse entry */
		odp_rwlock_write_lock(&gbl_args->snat_lock);
		if (snat_ptr->hash_value == hash_value)
			snat_ptr->reverse_nat_entry = dnat_ptr;
		else
			dnat_ptr->valid = 0;

		odp_rwlock_write_unlock(&gbl_args->snat_lock);

		if (odp_unlikely(gbl_args->appl.debug_mode)) {
			printf("add to dnat table: ");
			printf("%08x %d %08x %d %d %08x -> %p\n",
			       dnat_ipv4.src_ip, dnat_ipv4.src_port,
			       dnat_ipv4.dst_ip, dnat_ipv4.dst_port,
			       dnat_ipv4.protocol, snat_ipv4.src_ip,
			       snat_ptr->reverse_nat_entry);
		}

		/* 4. DO SNAT */
		return 4;
	}

	return 0;
}

/**
 * Process new entry
 *
 * This function takes care of unknown packets arrived from switch and going to
 * CPU.
 *
 * @param pkt		pointer to odp_packet_t
 *
 * @return		0 - success
 */
static inline int process_new_entry(odp_packet_t pkt)
{
	odph_ipv4hdr_t *ipv4hdr;
	odph_udphdr_t  *udphdr;
	uint16_t ethtype;
	uint32_t l3_offset;
	ipv4_5tuple_t ipv4;
	nat_entry_t *entry_ptr;
	uint32_t hash_value;
	int status;

	ipv4hdr = (odph_ipv4hdr_t *)odp_nat_packet_l3_ptr(pkt, &l3_offset,
							  &ethtype);

	/* For IPv6, don't do anything */
	if (odp_unlikely(ODPH_IPV4HDR_VER(ipv4hdr->ver_ihl) == ODPH_IPV6))
		return 0;

	/* udphdr is L4 header, could be udp, tcp or icmp header */
	udphdr = (odph_udphdr_t *)odp_nat_packet_l4_ptr(pkt, ipv4hdr, l3_offset,
							ethtype);

	if (odp_unlikely(!(ipv4hdr && udphdr)))
		return 0;

	if (odp_unlikely(0 != build_hash_search_key(&ipv4, ipv4hdr,
						    udphdr)))
		return 0;

	if (odp_likely(gbl_args->appl.dsa_mode)) {
		if (odp_unlikely(strip_dsa_hdr(pkt) == 1))
			return 1;
	}

	hash_value = XXH32((void *)&ipv4, sizeof(ipv4_5tuple_t), NAT_HASH_SEED);

	entry_ptr = find_hash_entry(gbl_args->snat_tbl, hash_value, &ipv4);
	if (entry_ptr == NULL) {
		status = learn_nat_entry(ipv4, hash_value, ipv4hdr, udphdr,
					 &entry_ptr);
		if (odp_likely(status == 4)) {
			/* only learning, skip SNAT */
			status = 0;
		}
		return status;
	}

	if (odp_unlikely(gbl_args->appl.debug_mode)) {
		printf("process_new_entry. ");
		printf("Found in snat table: %08x %d %08x %d %d\n",
		       ipv4.src_ip, ipv4.src_port, ipv4.dst_ip,
		       ipv4.dst_port, ipv4.protocol);
	}
	return 0;
}

static inline int supported_dsa_l3_pkt(odp_packet_t pkt)
{
	odph_ipv4hdr_t *ipv4hdr;
	uint16_t ethtype;
	uint32_t l3_offset;

	ipv4hdr = (odph_ipv4hdr_t *)odp_nat_packet_l3_ptr(pkt, &l3_offset,
							  &ethtype);
	if (!ipv4hdr)
		return 0;
	if (ODPH_IPV4HDR_VER(ipv4hdr->ver_ihl) != ODPH_IPV4)
		return 0;
	if ((ipv4hdr->proto != ODPH_IPPROTO_UDP) &&
	    (ipv4hdr->proto != ODPH_IPPROTO_TCP) &&
	    (ipv4hdr->proto != ODPH_IPPROTO_ICMPv4))
		return 0;

	return 1;
}

static inline int supported_l3_pkt(odp_packet_t pkt)
{
	odph_ipv4hdr_t *ipv4hdr;

	ipv4hdr = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	if (!ipv4hdr)
		return 0;
	if (ODPH_IPV4HDR_VER(ipv4hdr->ver_ihl) != ODPH_IPV4)
		return 0;
	if ((ipv4hdr->proto != ODPH_IPPROTO_UDP) &&
	    (ipv4hdr->proto != ODPH_IPPROTO_TCP) &&
	    (ipv4hdr->proto != ODPH_IPPROTO_ICMPv4))
		return 0;

	return 1;
}

static inline int send_to_snat(odp_packet_t pkt, uint8_t pkt_from_tap)
{
	odph_ipv4hdr_t *ipv4hdr;
	odph_udphdr_t  *udphdr;
	uint16_t ethtype, target_port;
	uint32_t l3_offset, target_ip;
	ipv4_5tuple_t snat_ipv4;
	nat_entry_t *entry_ptr;
	uint32_t hash_value;
	int status;

	ipv4hdr = (odph_ipv4hdr_t *)odp_nat_packet_l3_ptr(pkt, &l3_offset,
							  &ethtype);

	/* For IPv6, don't do anything */
	if (odp_unlikely(ODPH_IPV4HDR_VER(ipv4hdr->ver_ihl) == ODPH_IPV6))
		return 0;

	/* udphdr is L4 header, could be udp, tcp or icmp header */
	udphdr = (odph_udphdr_t *)odp_nat_packet_l4_ptr(pkt, ipv4hdr, l3_offset,
							ethtype);
	if (odp_likely(gbl_args->appl.dsa_mode)) {
		if (odp_likely(pkt_from_tap == 0))
			snat_dsa_processing(pkt);
	}

	if (odp_unlikely(!(ipv4hdr && udphdr))) {
		if (odp_unlikely(gbl_args->appl.debug_mode)) {
			if (!udphdr) {
				printf("send_to_snat invalid udphdr. ");
				printf("check ethtype after DSA header\n");
			} else {
				printf("send_to_snat invalid ipv4hdr\n");
			}
		}
		return 0;
	}

	if (odp_unlikely(0 != build_hash_search_key(&snat_ipv4, ipv4hdr,
						    udphdr))) {
		return 1;
	}

	hash_value = XXH32((void *)&snat_ipv4, sizeof(ipv4_5tuple_t),
			   NAT_HASH_SEED);

	entry_ptr = find_hash_entry(gbl_args->snat_tbl, hash_value, &snat_ipv4);

	if (odp_unlikely(entry_ptr == NULL)) {
		/* aged out NAT entry can still be active in the switch */
		status = learn_nat_entry(snat_ipv4, hash_value, ipv4hdr, udphdr,
					 &entry_ptr);
		if (odp_unlikely(status != 4))
			return status;
	} else {
		if (odp_unlikely(gbl_args->appl.debug_mode)) {
			printf("Found in snat table: %08x %d %08x %d %d %08x\n",
			       snat_ipv4.src_ip, snat_ipv4.src_port,
			       snat_ipv4.dst_ip, snat_ipv4.dst_port,
			       snat_ipv4.protocol, target_ip);
		}
	}

	/* Perform NAT */
	/* working without read locks. the entry can be removed from the table
	 * during packet modification */
	if (odp_unlikely(entry_ptr == NULL))
		return 1;

	target_ip = entry_ptr->target_ip;
	target_port = entry_ptr->target_port;

	if (odp_unlikely((!entry_ptr->valid) ||
			 (entry_ptr->hash_value != hash_value))) {
		return 1;
	}

	if (odp_unlikely(target_ip == 0))
		return 0;

	/* zero aging counter */
	entry_ptr->counter = 0;
	/* entry_ptr->reverse_nat_entry->counter = 0; */

	do_snat(ipv4hdr, udphdr, target_ip, target_port, snat_ipv4.protocol);
	return 0;
}

static inline int send_to_dnat(odp_packet_t pkt)
{
	odph_ipv4hdr_t *ipv4hdr;
	odph_udphdr_t  *udphdr;
	uint32_t hash_value, target_ip;
	uint16_t ethtype, target_port;
	uint32_t l3_offset;
	nat_entry_t cur_entry, *entry_ptr;
	ipv4_5tuple_t ipv4;

	ipv4hdr = (odph_ipv4hdr_t *)odp_nat_packet_l3_ptr(pkt, &l3_offset,
							  &ethtype);
	/* For IPv6, don't do anything */
	if (odp_unlikely(ODPH_IPV4HDR_VER(ipv4hdr->ver_ihl) == ODPH_IPV6))
		return 0;

	udphdr = (odph_udphdr_t *)odp_nat_packet_l4_ptr(pkt, ipv4hdr, l3_offset,
							ethtype);

	if (odp_unlikely(!(ipv4hdr && udphdr))) {
		if (odp_unlikely(gbl_args->appl.debug_mode)) {
			if (!udphdr) {
				printf("send_to_dnat invalid udphdr. ");
				printf("check ethtype after DSA header\n");
			} else {
				printf("send_to_dnat invalid ipv4hdr\n");
			}
		}
	}

	if (odp_unlikely(0 != build_hash_search_key(&ipv4, ipv4hdr, udphdr)))
		return 1;

	hash_value = XXH32((void *)&ipv4, sizeof(ipv4_5tuple_t), NAT_HASH_SEED);

	entry_ptr = find_hash_entry(gbl_args->dnat_tbl, hash_value, &ipv4);

	if (odp_unlikely(entry_ptr == NULL)) {
		if (odp_unlikely(gbl_args->appl.debug_mode))
			printf("Not found in dnat table: %08x %d %08x %d %d\n",
			       ipv4.src_ip, ipv4.src_port, ipv4.dst_ip,
			       ipv4.dst_port, ipv4.protocol);
		return 1;
	}

	/* working without read locks. the entry can be removed from the table
	 * during packet modification */
	target_ip = entry_ptr->target_ip;
	target_port = entry_ptr->target_port;

	if (odp_unlikely((!entry_ptr->valid) ||
			 (entry_ptr->hash_value != hash_value)))
		return 1;

	/* zero aging counters */
	entry_ptr->counter = 0;
	if (odp_likely(entry_ptr->reverse_nat_entry != NULL))
		entry_ptr->reverse_nat_entry->counter = 0;

	if (odp_unlikely(gbl_args->appl.debug_mode)) {
		printf("Found in dnat table: %08x %d %08x %d %d\n",
		       ipv4.src_ip, ipv4.src_port, ipv4.dst_ip,
		       ipv4.dst_port, ipv4.protocol);
	}

	do_dnat(ipv4hdr, udphdr, target_ip, target_port, ipv4.protocol);
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
			//if ((ntohs(eth->dsa.vid) & VID_MASK) == gbl_args->appl.lan_vid)
			//Forward DSA tag Routed bit
			if (eth->dsa.word1_byte3 & 0x2)
				return DATA_PLANE_FROM_LAN;
			else
				return DATA_PLANE_FROM_WAN;
            } else { // Control Plane
			// If from LAN VID
			//if ((ntohs(eth->dsa.vid) & VID_MASK) == gbl_args->appl.lan_vid)
			if (eth->dsa.word1_byte3 & 0x2)
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
	odp_packet_t pkt, pkt_copy;
	odp_packet_t send_pkt_tbl[MAX_PKT_BURST];
	unsigned i;
	int proceed = 0;//0: to send, 1: to drop, 2: been sent
	int sent = 0;
	int control_sent = 0;
	int res;

	for (i = 0; i < num; ++i) {
		pkt = pkt_tbl[i];
		if (num - i > PREFETCH_SHIFT)
			odp_packet_prefetch(pkt_tbl[i + PREFETCH_SHIFT], ODPH_ETHHDR_LEN, ODPH_IPV4HDR_LEN + 12);

		if (odp_unlikely(gbl_args->appl.debug_mode)) {
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
                if (odp_unlikely(gbl_args->appl.debug_mode)) {
                    printf("It is DATA_PLANE_FROM_LAN\n");
                }
		proceed = send_to_snat(pkt, 0);
                break;
            case DATA_PLANE_FROM_WAN:
                if (odp_unlikely(gbl_args->appl.debug_mode)) {
                    printf("It is DATA_PLANE_FROM_WAN\n");
                }
		proceed = send_to_dnat(pkt);
                break;
            case CONTROL_PLANE_TO_CPU_LAN:
		if (odp_unlikely(gbl_args->appl.debug_mode))
			printf("It is CONTROL_PLANE_TO_CPU_LAN\n");

		if (supported_dsa_l3_pkt(pkt)) {
			/* unknown pkt from the switch, learn it */
			if (odp_unlikely(gbl_args->appl.debug_mode))
				printf("Unknown pkt to CPU lan\n");

			process_new_entry(pkt);
			proceed = process_tocpu_lan(pkt, 0);
		} else {
			proceed = process_tocpu_lan(pkt, 1);
		}
                break;
            case CONTROL_PLANE_TO_CPU_WAN:
                if (odp_unlikely(gbl_args->appl.debug_mode)) {
                    printf("It is CONTROL_PLANE_TO_CPU_WAN\n");
		}
		proceed = process_tocpu_wan(pkt, 1);
                break;
            case CONTROL_PLANE_FROM_CPU_LAN:
                if (odp_unlikely(gbl_args->appl.debug_mode)) {
                    printf("It is CONTROL_PLANE_FROM_CPU_LAN\n");
                }
		proceed = process_fromcpu_lan(pkt);
                break;
            case CONTROL_PLANE_FROM_CPU_WAN:
                if (odp_unlikely(gbl_args->appl.debug_mode)) {
                    printf("It is CONTROL_PLANE_FROM_CPU_WAN\n");
                }
		if (supported_l3_pkt(pkt)) {
			if (odp_unlikely(gbl_args->appl.debug_mode))
				printf("L3 pkt from tap WAN\n");

			add_dsa_snat_fromcpu(pkt, pktio);
			proceed = send_to_snat(pkt, 1);
			if (proceed == 1) {
				if (odp_unlikely(strip_dsa_hdr(pkt) == 1)) {
					proceed = 1;
				} else {
					proceed = process_fromcpu_wan(pkt,
								      pktio);
				}
			}
		} else {
			proceed = process_fromcpu_wan(pkt, pktio);
		}
                break;
            default:
                if (odp_unlikely(gbl_args->appl.debug_mode)) {
                    printf("It is UNKNOWN TYPE\n");
                }
                odp_packet_free(pkt);
                break;
        }

        switch (proceed) {
            case 0:
                send_pkt_tbl[sent++] = pkt;
                if (odp_unlikely(gbl_args->appl.debug_mode)) {
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
                if (odp_unlikely(gbl_args->appl.debug_mode))
			printf("Dropped\n");
                break;
            case 2:
		control_sent++;
                if (odp_unlikely(gbl_args->appl.debug_mode))
			printf("Sent to Control Plane\n");
            default:
                break;
        }
	}

	if (odp_likely(sent))
		sent = odp_pktout_send(pktio->pktout, send_pkt_tbl, sent);

	return (sent + control_sent);
}

static void print_nat_table(nat_entry_t nat_tbl[][NAT_TBL_DEPTH], unsigned int tbl_size, unsigned int tbl_depth, const char *msg)
{
	unsigned int i, j, num_entries = 0;
	unsigned int ip;

	printf("\t %s\n", msg);
	printf("\t Hash   Dep  Src IP       PRT   Dest IP      PRT   Prtcl  Target IP    PRT   TimeStamp   \n");
	printf("\t ----------------------------------------------------------------------------------------\n");
	for(i=0; i<tbl_size; i++)
	{
		for(j=0; j<tbl_depth; j++)
		{
			if(nat_tbl[i][j].valid)
			{
				printf("\t %05X  %3X  ", i, j);
				ip = nat_tbl[i][j].ipv4_5tuple.src_ip;
				printf("%02X.%02X.%02X.%02X  ", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip >> 0) & 0xff);
				printf("%04X  ", nat_tbl[i][j].ipv4_5tuple.src_port);
				ip = nat_tbl[i][j].ipv4_5tuple.dst_ip;
				printf("%02X.%02X.%02X.%02X  ", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip >> 0) & 0xff);
				printf("%04X  ", nat_tbl[i][j].ipv4_5tuple.dst_port);
				printf("%02X     ", nat_tbl[i][j].ipv4_5tuple.protocol);
				ip = nat_tbl[i][j].target_ip;
				printf("%02X.%02X.%02X.%02X  ", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip >> 0) & 0xff);
				printf("%04X  ", nat_tbl[i][j].target_port);
				printf("%d\n", nat_tbl[i][j].counter);
				num_entries ++;
			}
		}
	}
	printf("\t ----------------------------------------------------------------------------------------\n");
	printf("\t number of entries: %d\n\n", num_entries);
	return;
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
	int num_pktio;
	odp_pktin_queue_t pktin;
	int pktio = 0;
	thread_args_t *thr_args = arg;
	stats_t *stats = thr_args->stats;

	num_pktio = thr_args->num_pktio;
	pktin     = thr_args->pktio[pktio].pktin;
	cur_pktio = &thr_args->pktio[pktio];

	odp_barrier_wait(&barrier);

	/* Loop packets */
	while (!exit_threads) {
		int sent;
		unsigned tx_drops;

		if (num_pktio > 1) {
			pktin     = thr_args->pktio[pktio].pktin;
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
		sent = odp_unlikely(sent < 0) ? 0 : sent;
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
	odp_pktio_config_t config;
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

	odp_pktio_config_init(&config);

	/* Checksum Validation */
	config.pktin.bit.ipv4_chksum = capa.config.pktin.bit.ipv4_chksum & 0x1;
	config.pktin.bit.udp_chksum = capa.config.pktin.bit.udp_chksum & 0x1;
	config.pktin.bit.tcp_chksum = capa.config.pktin.bit.tcp_chksum & 0x1;
	/* Checksum  Generation*/
	config.pktout.bit.ipv4_chksum = capa.config.pktout.bit.ipv4_chksum & 0x1;
	config.pktout.bit.udp_chksum = capa.config.pktout.bit.udp_chksum & 0x1;
	config.pktout.bit.tcp_chksum = capa.config.pktout.bit.tcp_chksum & 0x1;
	/* Rx dropping on errors */
	config.pktin.bit.drop_ipv4_err = 0;
	config.pktin.bit.drop_udp_err = 0;
	config.pktin.bit.drop_tcp_err = 0;

	/* Configure DSA mode
	* Marvell proprietary. Use one of the two upper bits in
	* odp_pktout_queue_param_t struct (not in use by ODP)
	* to indicate MUSDK pktio that DSA awareness should be turned on
	*/
	if (gbl_args->appl.dsa_mode &&
	    (capa.config.pktout.all_bits & MV_EXT_DSA_MODE_BIT))
		config.pktout.all_bits |= (uint64_t)MV_EXT_DSA_MODE_BIT;

	odp_pktio_config(pktio, &config);

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

static uint64_t print_stats(int num_workers, stats_t *thr_stats, int timeout,
			    uint64_t *pkts_prev, uint64_t *maximum_pps)
{
	uint64_t rx_drops = 0;
	uint64_t tx_drops = 0;
	uint64_t pkts = 0;
	uint64_t pps;
	int i;

	for (i = 0; i < num_workers; i++) {
		pkts += thr_stats[i].s.packets;
		rx_drops += thr_stats[i].s.rx_drops;
		tx_drops += thr_stats[i].s.tx_drops;
	}

	pps = (pkts - *pkts_prev) / timeout;
	if (pps > *maximum_pps)
		*maximum_pps = pps;

	printf("%" PRIu64 " pps, %" PRIu64 " max pps, ",  pps, *maximum_pps);
	printf(" %" PRIu64 " rx drops, %" PRIu64 " tx drops\n", rx_drops,
	       tx_drops);

	*pkts_prev = pkts;
	return pkts;
}

static inline void clear_nat_entry(int index, int depth)
{
	gbl_args->snat_tbl[index][depth].reverse_nat_entry->valid = 0;
	gbl_args->snat_tbl[index][depth].valid = 0;
}

static inline void aging_hash_entry_scan(int idx, uint32_t counter_update)
{
	int j;

	for (j = 0; j < NAT_TBL_DEPTH; j++) {
		odp_rwlock_write_lock(&gbl_args->snat_lock);
		if (gbl_args->snat_tbl[idx][j].valid) {
			gbl_args->snat_tbl[idx][j].counter += counter_update;
			/* snat_tbl[i][j].reverse_nat_entry->counter +=
			  timeout; */
			if (odp_unlikely(gbl_args->snat_tbl[idx][j].counter >=
						gbl_args->appl.aging_time)) {
				clear_nat_entry(idx, j);
			}
		}
		odp_rwlock_write_unlock(&gbl_args->snat_lock);
	}
}

static int nat_aging_and_stats(int num_workers, stats_t *thr_stats,
			       int duration, int timeout, int aging_enable)
{
	uint64_t pkts = 0;
	uint64_t maximum_pps = 0;
	uint64_t pkts_prev = 0;
	uint32_t i;
	int elapsed = 0;
	int stats_enabled = 1;
	int loop_forever = (duration == 0);
	int dump_interval = 20;
	int cur_chunk = 0;
	uint16_t num_chunks = 512;
	uint32_t chunk_size = NAT_TBL_SIZE / num_chunks;
	uint32_t aging_start_idx;
	uint32_t aging_end_idx;
	int passed_usec = 0;
	int sleep_usec = 50;
	struct timespec time1, time2;
	int counter = 0;

	if (gbl_args->appl.aging_time == 0) {
		aging_enable = 0;
	} else {
		if (num_chunks * sleep_usec < 1000)
			sleep_usec = 1000 / num_chunks;

		if ((num_chunks * sleep_usec / 1000) >
		    (int)gbl_args->appl.aging_time) {
			num_chunks = gbl_args->appl.aging_time * 1000 /
				sleep_usec;

			/* num_chunks should be a power of 2 and smaller than
			 * the current value */
			while (num_chunks >>= 1)
				counter++;

			if (counter > 0)
				counter--;

			num_chunks = 2 << counter;
		}

		time1.tv_sec = sleep_usec / 1000;
		time1.tv_nsec = (sleep_usec % 1000) * 1000000L;

		if (NAT_TBL_SIZE % num_chunks != 0) {
			printf("Error: invalid number of aging scan chunks\n");
			return -1;
		}
	}

	if (dump_interval <= 0)
		dump_interval = 1;

	if (timeout <= 0) {
		stats_enabled = 0;
		gbl_args->appl.print_table = 0;
		timeout = 1;
	}

	/* Wait for all threads to be ready*/
	odp_barrier_wait(&barrier);

	do {
		if (aging_enable) {
			aging_start_idx = cur_chunk * chunk_size;
			aging_end_idx = aging_start_idx + chunk_size;

			for (i = aging_start_idx; i < aging_end_idx; i++) {
				aging_hash_entry_scan(i, num_chunks *
						      sleep_usec / 1000);
			}

			if (odp_unlikely(++cur_chunk == num_chunks))
				cur_chunk = 0;

			nanosleep(&time1, &time2);
			passed_usec += sleep_usec;

			if (odp_unlikely(passed_usec >= timeout * 1000)) {
				passed_usec = 0;
				elapsed += timeout;

				if (stats_enabled)
					pkts = print_stats(num_workers,
							   thr_stats,
							   timeout,
							   &pkts_prev,
							   &maximum_pps);
			}

			if (odp_unlikely((gbl_args->appl.print_table == 1) &&
					 (elapsed % dump_interval == 0))) {
				print_nat_table(gbl_args->snat_tbl,
						NAT_TBL_SIZE, NAT_TBL_DEPTH,
						"SNAT Table Dump");
				print_nat_table(gbl_args->dnat_tbl,
						NAT_TBL_SIZE, NAT_TBL_DEPTH,
						"DNAT Table Dump");
			}
		} else {
			sleep(timeout);

			if (stats_enabled)
				pkts = print_stats(num_workers, thr_stats,
						   timeout, &pkts_prev,
						   &maximum_pps);

			elapsed += timeout;
		}

	} while (!glb_stop && (loop_forever || (elapsed < duration)));

	if (stats_enabled)
		printf("TEST RESULT: %" PRIu64 " maximum packets per second.\n",
		       maximum_pps);

	return pkts > 100 ? 0 : -1;
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
	       "  -o, --aging time for NAT entries in seconds (0 - 3600)\n"
	       "		Default value is 300 seconds\n"
	       "		0 - aging disabled\n"
	       "  -c, --count <number> CPU count.\n"
	       "  -a, --accuracy <number> Time in seconds get print statistics\n"
	       "                          and aging task resolution\n"
	       "                          (default is 1 second).\n"
	       "  -g, --debug debug mode\n"
	       "  -p, --print NAT table\n"
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
		{"print", no_argument, NULL, 'p'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts =  "+c:+a:i:d:o:l:w:shgp";

	/* let helper collect its own arguments (e.g. --odph_proc) */
	odph_parse_options(argc, argv, shortopts, longopts);

	appl_args->time = 0; /* loop forever if time to run is 0 */
	appl_args->accuracy = 1; /* get and print pps stats second */
	appl_args->error_check = 0; /* don't check packet errors by default */
	appl_args->dsa_mode = 0;
	appl_args->lan_vid = INVALID_VID;
	appl_args->aging_time = DEFAULT_AGING_TIME;

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
			     token = strtok(NULL, ","), i++);

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
			if (appl_args->aging_time > MAX_AGING_TIME) {
				appl_args->aging_time = MAX_AGING_TIME;
				printf("Aging time is set to its maximum value = 3600\n");
			}
			if (appl_args->aging_time == 0)
				printf("Aging disabled\n");
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
		appl_args->dsa_mode = 1;
            break;

		case 'g':
			appl_args->debug_mode = 1;
			break;

		case 'p':
			appl_args->print_table = 1;
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

	if ((appl_args->dsa_mode == 1) &&
		((appl_args->if_wan_str == NULL) || (appl_args->lan_vid == INVALID_VID))) {
		printf("DSA mode misses lan and wan vids\n");
		exit(EXIT_FAILURE);
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

	odp_rwlock_init(&args->snat_lock);
	odp_rwlock_init(&args->dnat_lock);
}

static void sig_int_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM) {
		glb_stop = 1;
		exit_threads = 1;
	}
}

/**
 * ODP NAT main function
 */
int main(int argc, char *argv[])
{
	odph_odpthread_t thread_tbl[MAX_WORKERS];
	odp_pool_t pool, pool_tap;
	int i;
	int cpu;
	int num_workers;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	int ret;
	stats_t *stats;
	int if_count;
	odp_instance_t instance;
	odp_init_t odp_init_params;
	odp_cpumask_t worker_cpu_mask;
	odp_cpumask_t control_cpu_mask;

	memset(&odp_init_params, 0, sizeof(odp_init_params));
	odp_cpumask_zero(&control_cpu_mask);
	odp_cpumask_zero(&worker_cpu_mask);
	odp_cpumask_set(&control_cpu_mask, 0);

	for (i = 0; i < MAX_WORKERS; i++)
		odp_cpumask_set(&worker_cpu_mask, i);

	odp_init_params.worker_cpus = &worker_cpu_mask;
	odp_init_params.control_cpus = &control_cpu_mask;

	if (signal(SIGINT, sig_int_handler) != 0) {
		printf("Error: register to SIGINT failed\n");
		exit(EXIT_FAILURE);
	}

	if (signal(SIGTERM, sig_int_handler) != 0) {
		printf("Error: register to SIGTERM failed\n");
		exit(EXIT_FAILURE);
	}

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &odp_init_params, NULL)) {
		printf("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		printf("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	gbl_args = malloc(sizeof(args_t));

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

	/* Multiply the pool size by factor of 2 since it is shared between
	 *all the pktio's in the system (ODP_CONFIG_PKTIO_ENTRIES)
	 */
	params.pkt.num     = (SHM_PKT_POOL_SIZE * num_workers) * 2;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet pool", &params);

	if (pool == ODP_POOL_INVALID) {
		printf("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	pool_tap = odp_pool_create("packet tap pool", &params);
	gbl_tap_pool = pool_tap;
	if (pool_tap == ODP_POOL_INVALID) {
		printf("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool_tap);

	bind_workers();

	for (i = 0; i < if_count; ++i) {
		const char *dev = gbl_args->appl.if_names[i];
		int num_rx, num_tx;

		num_rx = gbl_args->pktios[i].num_rx_thr;
		num_tx = gbl_args->pktios[i].num_tx_thr;

		if (create_pktio(dev, i, num_rx, num_tx,
			(i >= gbl_args->appl.if_phy_count) ? pool_tap : pool))
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

	ret = nat_aging_and_stats(num_workers, stats, gbl_args->appl.time,
				gbl_args->appl.accuracy, 1);

	/* Master thread waits for other threads to exit */
	for (i = 0; i < num_workers; ++i)
		odph_odpthreads_join(&thread_tbl[i]);

	/* TODO: remove this delay after handling shadow free by pktio */
	sleep(1);
	for (i = 0; i < if_count; ++i) {
		odp_pktio_t pktio;

		pktio = gbl_args->pktios[i].pktio;
		ret   = odp_pktio_stop(pktio);
		if (ret) {
			printf("Error: unable to stop %s\n",
			       gbl_args->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}
		ret   = odp_pktio_close(pktio);
		if (ret) {
			printf("Error: unable to close %s\n",
			       gbl_args->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}
	}

	free(gbl_args->appl.if_names);
	free(gbl_args->appl.if_str);
	free(gbl_args->appl.if_wan_str);

	if (odp_pool_destroy(pool)) {
		printf("Error: pool destroy\n");
		exit(EXIT_FAILURE);
	}

	if (odp_pool_destroy(pool_tap)) {
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
