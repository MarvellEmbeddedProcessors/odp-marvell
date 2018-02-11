/* Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#ifndef __MV_NMP_GUEST_UTILS_H__
#define __MV_NMP_GUEST_UTILS_H__

#include <odp_packet_musdk.h>

struct pp2_ppio_bpool_info {
	char	bpool_name[20];
};

struct pp2_ppio_info {
	char				 ppio_name[20];
	u32				 num_bpools;
	struct pp2_ppio_bpool_info	*bpool_info;
};

struct pp2_info {
	u32			 num_ports;
	struct pp2_ppio_info	 *port_info;
};

/*
 * nmp_guest mode related functions.
 */
int guest_util_get_relations_info(char *buff, struct pp2_info *pp2_info);

#endif /*__MV_NMP_GUEST_UTILS_H__*/

