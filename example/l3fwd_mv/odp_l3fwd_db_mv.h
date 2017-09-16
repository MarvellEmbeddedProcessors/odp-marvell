/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_L3FWD_DB_MV_H_
#define _ODP_L3FWD_DB_MV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>
#include <odp/helper/eth.h>

#if ODP_L3FWD_5TUPLE == 0
#define _DST_IP_FRWD_
#endif
#define OIF_LEN 32
#define MAX_DB  65536
#define MAX_STRING  32

#ifndef _DST_IP_FRWD_
#define _IPV6_ENABLED_
#endif
/**
 * Max number of flows
 */
#define FWD_MAX_FLOW_COUNT	(1 << 16)

/**
 * Default hash entries in a bucket
 */
#define FWD_DEF_BUCKET_ENTRIES	4

/**
 * IPv4 hash key size
 */
#define IPV4_5TUPLE_KEY_SIZE (sizeof(int32_t)+sizeof(int32_t)+ \
						sizeof(int16_t)+sizeof(int16_t)+sizeof(int8_t))

/**
 * IPv6 hash key size
 */
#define IPV6_5TUPLE_KEY_SIZE (5 * sizeof(uint64_t))

/**
 * IP address range (subnet)
 */
typedef struct ip_addr_range_s {
	uint32_t  addr;     /**< IP address, host endianness */
	uint32_t  depth;    /**< subnet bit width */
} ip_addr_range_t;

typedef struct ipv6_addr_range_s {
	union ipv6_addr_u {
		struct u64_s {
			uint64_t  ipv6_hi;     /**< IP address, host endianness */
			uint64_t  ipv6_lo;     /**< IP address, host endianness */
		} u64;
		struct u16_s {
			uint16_t ipv6_u16[8];
		} u16;
		struct u8_s {
			uint8_t ipv6_u8[16];
		} u8;
	} addr;
	uint32_t  prefix;    		/**< subnet bit width */
} ipv6_addr_range_t;

/**
 * TCP/UDP flow
 */
 typedef struct tuple5_s {
	union tuple5_u {
		struct ipv4_5t_s{
			int32_t src_ip;
			int32_t dst_ip;
			int16_t src_port;
			int16_t dst_port;
			int8_t  proto;
			int8_t  pad1;
			int16_t pad2;
#ifdef _IPV6_ENABLED_
			int64_t pad3;
			int64_t pad4;
			int64_t pad5;
#endif
		} ipv4_5t;
		struct ip_5t_s{
			int64_t hi64;
			int64_t lo64;
#ifdef _IPV6_ENABLED_
			int64_t pad6;
			int64_t pad7;
			int64_t pad8;
#endif
		} ip_5t;
#ifdef _IPV6_ENABLED_
		struct ipv6_5t_s{
			uint8_t src_ipv6[16];
			uint8_t dst_ipv6[16];
			int16_t src_port;
			int16_t dst_port;
			int8_t  proto;
			int8_t  pad9;
			int16_t pad10;
		} ipv6_5t;
#endif
	} u5t;
	uint8_t ip_protocol;	/*ODPH_IPV4 or ODPH_IPV6*/
} tuple5_t ODP_ALIGNED_CACHE;

/**
 * Forwarding data base entry
 */
typedef struct fwd_db_entry_s {
	struct fwd_db_entry_s *next;          /**< Next entry on list */
	char				oif[OIF_LEN]; /**< Output interface name */
	uint8_t				oif_id;	      /**< Output interface idx */
	odph_ethaddr_t		src_mac;      /**< Output source MAC */
	odph_ethaddr_t		dst_mac;      /**< Output destination MAC */
#ifndef _DST_IP_FRWD_
	union ip_hdr_u{
		struct ipv4_s {
			ip_addr_range_t		src_subnet;  /*subnet previously*/     /**< Subnet for this router */
			ip_addr_range_t		dst_subnet;
			uint16_t			src_port;
			uint16_t			dst_port;
			uint8_t				protocol;	/*0 - UDP, 1 - TCP */
		} ipv4;
		struct ipv6_s {
			ipv6_addr_range_t	src_subnet;  	/*subnet previously*/     /**< Subnet for this router */
			ipv6_addr_range_t	dst_subnet;
			uint16_t			src_port;
			uint16_t			dst_port;
			uint8_t				protocol;		/*0 - UDP, 1 - TCP */
		} ipv6;
	} u;
	uint8_t ip_protocol;	/*ODPH_IPV4 or ODPH_IPV6*/
#else
	ip_addr_range_t		subnet;
#endif
} fwd_db_entry_t;

/**
 * Forwarding data base
 */
typedef struct fwd_db_s {
	uint32_t          index;          /**< Next available entry */
	fwd_db_entry_t   *list;           /**< List of active routes */
	fwd_db_entry_t    array[MAX_DB];  /**< Entry storage */
} fwd_db_t;

/** Global pointer to fwd db */
extern fwd_db_t *fwd_db;

/**
 * Initialize FWD DB
 */
void init_fwd_db(void);

/**
 * Initialize forward lookup cache based on hash
 */
void init_fwd_hash_cache(void);

/**
 * Create a forwarding database entry
 *
 * String is of the format "SubNet,Intf,NextHopMAC"
 *
 * @param input  Pointer to string describing route
 * @param oif  Pointer to out interface name, as a return value
 * @param dst_mac  Pointer to dest mac for output packet, as a return value
 *
 * @return 0 if successful else -1
 */
int create_fwd_db_entry(char *input, char **oif, uint8_t **dst_mac);

/**
 * Scan FWD DB entries and resolve output queue and source MAC address
 *
 * @param intf   Interface name string
 * @param portid Output queue for packet transmit
 * @param mac    MAC address of this interface
 */
void resolve_fwd_db(char *intf, int portid, uint8_t *mac);

/**
 * Display one forwarding database entry
 *
 * @param entry  Pointer to entry to display
 */
void dump_fwd_db_entry(fwd_db_entry_t *entry);

/**
 * Display the forwarding database
 */
void dump_fwd_db(void);

/**
 * Find a matching forwarding database entry
 *
 * @param key  ipv4/ipv6 tuple
 *
 * @return pointer to forwarding DB entry else NULL
 */
fwd_db_entry_t *find_fwd_db_entry(tuple5_t *key);

/**
 * Parse text string representing an IPv4 address or subnet
 *
 * String is of the format "XXX.XXX.XXX.XXX(/W)" where
 * "XXX" is decimal value and "/W" is optional subnet length
 *
 * @param ipaddress  Pointer to IP address/subnet string to convert
 * @param addr       Pointer to return IPv4 address, host endianness
 * @param depth      Pointer to subnet bit width
 * @return 0 if successful else -1
 */
int parse_ipv4_string(char *ipaddress, uint32_t *addr, uint32_t *depth);

/**
 * Parse text string representing an IPv6 address or subnet
 *
 * String is of the format "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX(/W)" where
 * "XXXX" is heximal value and "/W" is optional subnet length
 * Or condensed notation: XXXX:XXXX:XXXX:XXXX::(0/W)
 *
 * @param ipaddress  Pointer to IP address/subnet string to convert
 * @param addr_hi    Pointer to return high 64B of IPv6 address, host endianness
 * @param addr_lo    Pointer to return low 64B of IPv6 address, host endianness
 * @param depth      Pointer to subnet bit width
 * @return 0 if successful else -1
 */
int parse_ipv6_string(char *ipaddress, uint64_t *addr_hi, uint64_t *addr_lo, uint32_t *depth);

#ifdef __cplusplus
}
#endif

#endif
