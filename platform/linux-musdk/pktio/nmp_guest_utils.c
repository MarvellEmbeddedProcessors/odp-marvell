/* Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#include <odp_posix_extensions.h>
#include <odp_debug_internal.h>

#include "nmp_guest_utils.h"

#define NMP_MAX_BUF_STR_LEN	256
#define SER_MAX_FILE_SIZE	(30 * 1024)

/*---------------------------*/
/*  Guest mode related functions  */
/*--------------------------*/

/**
 * json_buffer_to_input
 *
 * Description: search for a specified string and retrieve its integer value from a
 * JSON format buffer.
 *
 * NOTE: This function does not extract the values from regular JSON file. The file should
 * be according to the json_json_print_to_buffer macro above
 *
 * NOTE: Currently the macros parse only the matching string, and do not search in the input
 * buffer (meaning the calling order should be the same as the written order)
 *
 * An example for reading from JSON format file:
 *	Retireve pp2_id and pool_id:
 *		 json_buffer_to_input(sec, "pp2_id", pp2_id);
 *		 json_buffer_to_input(sec, "pool_id", pool_id);
 *
 * @param[in]	buf	A pointer to the reading buffer.
 * @param[in]	_str	A pointer to the matching string
 *
 * @param[out]	_p	The parameter to update with the value found
 */
#define json_buffer_to_input(buff, _str, _p)					\
do {										\
	int	rc, res = 0;							\
	u64	res1 = 0;							\
	int	found = 0;							\
	char	*tok, *tmp_tok;							\
	/*Go over the input buffer untile the match str is found. */		\
	do {									\
		tok = strsep(&buff, "\n");					\
		/*if a "{" is found, go to the next line in buffer. */		\
		tmp_tok = strstr(tok, "{");					\
		if (tmp_tok != NULL)						\
			continue;						\
		/*if a "}" is found, go to the next line in buffer. */		\
		tmp_tok = strstr(tok, "}");					\
		if (tmp_tok != NULL)						\
			continue;						\
		/*if str is not found, exit with error */			\
		if (strstr(tok, _str) == NULL) {				\
			ODP_ERR("%s not found\n", _str);				\
			break;							\
		}								\
		/*search for the ": " string, if not found, exit with error */	\
		tmp_tok = strstr(tok, ": ");					\
		if (tmp_tok == NULL) {						\
			ODP_ERR("Invalid string(%s)!\n", tok);			\
			break;							\
		}								\
		/* check if string contains a "," at the end and remove */	\
		if (strstr(tmp_tok, "0x") != NULL) {				\
			rc = kstrtou64(&tmp_tok[strlen(": 0x")], 16, &res1);	\
			if (rc != 0) {						\
				ODP_ERR("Invalid string(%s)!\n", tok);		\
				break;						\
			}							\
			_p = res1;						\
			found = 1;						\
		} else {							\
			/* treat the val as integer */				\
			rc = kstrtoint(&tmp_tok[strlen(": ")], 10, &res);	\
			if (rc != 0) {						\
				ODP_ERR("Invalid string(%s)!\n", tok);		\
				break;						\
			}							\
			_p = res;						\
			found = 1;						\
		}								\
	} while (!found);							\
} while (0)

 /**
 * json_buffer_to_input_str
 *
 * Description: search for a specified string and retrieve its string value from a
 * JSON format buffer.
 *
 * NOTE: This function does not extract the values from regular JSON file. The file should
 * be according to the json_json_print_to_buffer macro above
 *
 * NOTE: Currently the macros parse only the matching string, and do not search in the input
 * buffer (meaning the calling order should be the same as the written order)
 *
 * An example for reading from JSON format file:
 *	Retireve pp2_id and pool_id:
 *		json_buffer_to_input_mac(sec, "mac_address", port->mac_data.mac);
 *
 * @param[in]	buf	A pointer to the reading buffer.
 * @param[in]	_str	A pointer to the matching string
 *
 * @param[out]	_p	The parameter to update with the value found
 */
#define json_buffer_to_input_str(buff, _str, _p)				\
do {										\
	int	found = 0;							\
	char	*tok, *tmp_tok;							\
	/*ascii_code for quotes. This is for checkpatch compatibility. */	\
	char	ascii_code = 34;						\
	/*Go over the input buffer untile the match str is found. */		\
	do {									\
		tok = strsep(&buff, "\n");					\
		/*if a "{" is found, go to the next line in buffer. */		\
		tmp_tok = strstr(tok, "{");					\
		if (tmp_tok != NULL)						\
			continue;						\
		/*if a "}" is found, go to the next line in buffer. */		\
		tmp_tok = strstr(tok, "}");					\
		if (tmp_tok != NULL)						\
			continue;						\
		/*if str is not found, exit with error */			\
		if (strstr(tok, _str) == NULL) {				\
			ODP_ERR("%s not found\n", _str);				\
			break;							\
		}								\
		/*search for the ": " string, if not found, exit with error */	\
		tmp_tok = strstr(tok, ": ");					\
		if (tmp_tok == NULL) {						\
			ODP_ERR("Invalid string(%s)!\n", tok);			\
			break;							\
		}								\
		/* check if string contains quotes, otherwise exit with error*/ \
		if (strncmp(&tmp_tok[2], &ascii_code, 1) != 0) {		\
			ODP_ERR("quotes not found (%s)!\n", tok);		\
			break;							\
		}								\
		/* check if string contains a "," at the end and remove */	\
		if (strstr(tmp_tok, ",") == NULL)				\
			tmp_tok[strlen(tmp_tok) - 1] = 0;			\
		else								\
			tmp_tok[strlen(tmp_tok) - 2] = 0;			\
		/* Copy the string */						\
		strcpy(_p, &tmp_tok[3]);					\
		found = 1;							\
	} while (!found);							\
} while (0)

int guest_util_get_relations_info(char *buff, struct pp2_info *pp2_info)
{
	u32	 i, j;
	char	*sec = NULL;
	int	 rc;
	char	*lbuff;
	char	 tmp_buf[NMP_MAX_BUF_STR_LEN];

	lbuff = kcalloc(1, SER_MAX_FILE_SIZE, GFP_KERNEL);
	if (lbuff == NULL)
		return -ENOMEM;

	if (!buff) {
		printf("buff is NULL\n");
		rc = -EINVAL;
		goto rel_info_exit1;
	}

	memcpy(lbuff, buff, SER_MAX_FILE_SIZE);

	sec = strstr(lbuff, "relations-info");
	if (!sec) {
		ODP_ERR("'relations-info' not found\n");
		rc = -EINVAL;
		goto rel_info_exit1;
	}

	json_buffer_to_input(sec, "num_pp2_ports", pp2_info->num_ports);
	ODP_PRINT("num_ports: %d\n", pp2_info->num_ports);

	pp2_info->port_info = kcalloc(1, sizeof(struct pp2_ppio_info) * pp2_info->num_ports, GFP_KERNEL);
	if (pp2_info->port_info == NULL) {
		rc = -ENOMEM;
		goto rel_info_exit1;
	}

	for (i = 0; i < pp2_info->num_ports; i++) {
		memset(tmp_buf, 0, sizeof(tmp_buf));
		snprintf(tmp_buf, sizeof(tmp_buf), "ppio-%d", i);
		json_buffer_to_input_str(sec, tmp_buf, pp2_info->port_info[i].ppio_name);
		ODP_PRINT("port: %d, ppio_name %s\n", i, pp2_info->port_info[i].ppio_name);

		json_buffer_to_input(sec, "num_bpools", pp2_info->port_info[i].num_bpools);
		ODP_PRINT("port: %d, num_pools %d\n", i, pp2_info->port_info[i].num_bpools);

		pp2_info->port_info[i].bpool_info = kcalloc(1, sizeof(struct pp2_ppio_bpool_info) *
							    pp2_info->port_info[i].num_bpools, GFP_KERNEL);
		if (pp2_info->port_info[i].bpool_info == NULL) {
			rc = -ENOMEM;
			goto rel_info_exit2;
		}
		for (j = 0; j < pp2_info->port_info[i].num_bpools; j++) {
			memset(tmp_buf, 0, sizeof(tmp_buf));
			snprintf(tmp_buf, sizeof(tmp_buf), "bpool-%d", j);
			json_buffer_to_input_str(sec, tmp_buf, pp2_info->port_info[i].bpool_info[j].bpool_name);
			ODP_PRINT("port: %d, pool name %s\n", i, pp2_info->port_info[i].bpool_info[j].bpool_name);
		}
	}
	kfree(lbuff);
	return 0;

rel_info_exit2:
	kfree(pp2_info->port_info);
rel_info_exit1:
	kfree(lbuff);
	return rc;
}
