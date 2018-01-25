/* Copyright (c) 2016, Marvell International Ltd.
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#include <odp_posix_extensions.h>
#include <odp_debug_internal.h>

#include "nmp_guest_utils.h"

#define NMP_MAX_BUF_STR_LEN		256
#define NMP_CFG_FILE_LOCAL_DIR		"./"
#define NMP_CFG_FILE_VAR_DIR		"/var/"
#define NMP_CFG_FILE_NAME_PREFIX	"musdk-nmp-config.txt"
#define SER_MAX_FILE_NAME	64
#define SER_MAX_FILE_SIZE	(30 * 1024)

#define NMP_MAX_NUM_CONTAINERS		4
#define NMP_MAX_NUM_LFS			8
#define NMP_GIE_MAX_TCS			8
#define NMP_GIE_MAX_Q_PER_TC		128
#define NMP_GIE_MAX_BPOOLS		16
#define NMP_GIE_MAX_BM_PER_Q		1

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


static int nmp_read_file_to_buf(char *file_name, char *buff, u32 size)
{
	size_t	s;
	int	fd;

	/* Open file */
	fd = open(file_name, O_RDONLY);
	if (fd == -1) {
		ODP_DBG("Failed to open file %s\n", file_name);
		return -EINVAL;
	}

	/* Read file */
	s = read(fd, buff, size);
	if (s == (size_t)-1) {
		ODP_ERR("error %d\n", errno);
		close(fd);
		return -EINVAL;
	}
	close(fd);
	printf("nmp-config file read from %s\n", file_name);
	sync();

	return 0;
}

static int nmp_range_validate(int value, int min, int max)
{
	if (((value) > (max)) || ((value) < (min))) {
		ODP_ERR("%s: value 0x%X (%d) is out of range [0x%X , 0x%X].\n",
			__func__, (value), (value), (min), (max));
		return -EINVAL;
	}
	return 0;
}

int nmp_read_cfg_file(char *cfg_file, struct nmp_params *params)
{
	u32				 i, j, k, rc;
	char				 file_name[SER_MAX_FILE_NAME];
	char				 buff[SER_MAX_FILE_SIZE];
	char				*sec = NULL;
	char				 tmp_buf[NMP_MAX_BUF_STR_LEN];
	char				 pp2_name[NMP_MAX_BUF_STR_LEN];
	struct nmp_lf_nicpf_params	*pf;
	u32				 num_lfs = 0;

	/* If cfg-file is provided, read the nmp-config from this location. Otherwise try to read either from
	 * local dir or from /var dir
	 */
	rc = nmp_read_file_to_buf(cfg_file, buff, SER_MAX_FILE_SIZE);
	if (rc) {
		snprintf(file_name, sizeof(file_name), "%s%s", NMP_CFG_FILE_LOCAL_DIR, NMP_CFG_FILE_NAME_PREFIX);
		rc = nmp_read_file_to_buf(file_name, buff, SER_MAX_FILE_SIZE);
		if (rc) {
			memset(file_name, 0, SER_MAX_FILE_NAME);
			snprintf(file_name, sizeof(file_name), "%s%s", NMP_CFG_FILE_VAR_DIR, NMP_CFG_FILE_NAME_PREFIX);
			rc = nmp_read_file_to_buf(file_name, buff, SER_MAX_FILE_SIZE);
			if (rc) {
				ODP_PRINT("nmp_config_file not found\n");
				return rc;
			}
		}
	}

	/* Check if there are nmp-params */
	sec = strstr(buff, "nmp_params");
	if (!sec) {
		ODP_ERR("nmp_params section not found!\n");
		return -EINVAL;
	}

	/* Check if pp2 is enabled */
	json_buffer_to_input(sec, "pp2_en", params->pp2_en);
	if (nmp_range_validate(params->pp2_en, 0, 1) != 0) {
		ODP_ERR("pp2_en not in tange!\n");
		return -EINVAL;
	}

	/* if pp2 enabled, set the pp2_params*/
	if (params->pp2_en) {
		sec = strstr(sec, "pp2_params");
		if (!sec) {
			ODP_ERR("'pp2_params' not found\n");
			return -EINVAL;
		}

		json_buffer_to_input(sec, "bm_pool_reserved_map", params->pp2_params.bm_pool_reserved_map);
		if (nmp_range_validate(params->pp2_params.bm_pool_reserved_map, 0, PP2_BPOOL_NUM_POOLS)) {
			ODP_PRINT("bm_pool_reserved_map not in tange!\n");
			rc = -EINVAL;
			goto read_cfg_exit1;
		}
	}

	/* Read number of containers */
	json_buffer_to_input(sec, "num_containers", params->num_containers);
	if (nmp_range_validate(params->num_containers, 1, NMP_MAX_NUM_CONTAINERS)) {
		ODP_PRINT("num_containers not in tange!\n");
		rc = -EINVAL;
		goto read_cfg_exit1;
	}

	params->containers_params = kcalloc(1, sizeof(struct nmp_container_params) *
					    params->num_containers, GFP_KERNEL);
	if (params->containers_params == NULL) {
		rc = -ENOMEM;
		goto read_cfg_exit1;
	}

	for (i = 0; i < params->num_containers; i++) {
		memset(tmp_buf, 0, sizeof(tmp_buf));
		snprintf(tmp_buf, sizeof(tmp_buf), "containers_params-%d", i);
		sec = strstr(sec, tmp_buf);
		if (!sec) {
			ODP_ERR("'containers_params' not found\n");
			rc = -EINVAL;
			goto read_cfg_exit1;
		}
		/* Read number of lfs */
		json_buffer_to_input(sec, "num_lfs", params->containers_params[i].num_lfs);
		if (nmp_range_validate(params->containers_params[i].num_lfs, 1, NMP_MAX_NUM_LFS) != 0) {
			rc = -EINVAL;
			goto read_cfg_exit1;
		}

		params->containers_params[i].lfs_params = kcalloc(1, sizeof(struct nmp_lf_params) *
								params->containers_params[i].num_lfs, GFP_KERNEL);
		if (params->containers_params[i].lfs_params == NULL) {
			rc = -ENOMEM;
			goto read_cfg_exit2;
		}
		num_lfs++;

		for (j = 0; j < params->containers_params[i].num_lfs; j++) {
			/* Read lf type*/
			json_buffer_to_input(sec, "lf_type", params->containers_params[i].lfs_params[j].type);
			if (nmp_range_validate(params->containers_params[i].lfs_params[j].type,
					       NMP_LF_T_NIC_NONE, NMP_LF_T_NIC_LAST - 1) != 0) {
				rc = -EINVAL;
				goto read_cfg_exit2;
			}

			if (params->containers_params[i].lfs_params[j].type == NMP_LF_T_NIC_PF) {
				/* Read nicpf*/
				pf = (struct nmp_lf_nicpf_params *)
				     &params->containers_params[i].lfs_params[j].u.nicpf;

				json_buffer_to_input(sec, "pci_en", pf->pci_en);
				if (nmp_range_validate(pf->pci_en, 0, 1) != 0) {
					rc = -EINVAL;
					goto read_cfg_exit2;
				}

				json_buffer_to_input(sec, "lcl_egress_qs_size", pf->lcl_egress_qs_size);
				if (!pf->lcl_egress_qs_size) {
					rc = -EINVAL;
					goto read_cfg_exit2;
				}

				json_buffer_to_input(sec, "lcl_ingress_qs_size", pf->lcl_ingress_qs_size);
				if (!pf->lcl_ingress_qs_size) {
					rc = -EINVAL;
					goto read_cfg_exit2;
				}

				json_buffer_to_input(sec, "dflt_pkt_offset", pf->dflt_pkt_offset);
				if (nmp_range_validate(pf->dflt_pkt_offset, 0, 1024) != 0) {
					rc = -EINVAL;
					goto read_cfg_exit2;
				}

				json_buffer_to_input(sec, "max_num_tcs", pf->max_num_tcs);
				if (nmp_range_validate(pf->max_num_tcs, 0, NMP_GIE_MAX_TCS) != 0) {
					rc = -EINVAL;
					goto read_cfg_exit2;
				}

				json_buffer_to_input(sec, "lcl_num_bpools", pf->lcl_num_bpools);
				if (nmp_range_validate(pf->lcl_num_bpools, 0, NMP_GIE_MAX_BPOOLS) != 0) {
					rc = -EINVAL;
					goto read_cfg_exit2;
				}

				for (k = 0; k < pf->lcl_num_bpools; k++) {
					memset(tmp_buf, 0, sizeof(tmp_buf));
					snprintf(tmp_buf, sizeof(tmp_buf), "lcl_bpools_params-%d", k);
					sec = strstr(sec, tmp_buf);
					if (!sec) {
						ODP_ERR("'lcl_bpools_params' not found\n");
						rc = -EINVAL;
						goto read_cfg_exit2;
					}

					json_buffer_to_input(sec, "max_num_buffs",
							     pf->lcl_bpools_params[k].max_num_buffs);
					if (!pf->lcl_bpools_params[k].max_num_buffs) {
						rc = -EINVAL;
						goto read_cfg_exit2;
					}

					json_buffer_to_input(sec, "buff_size", pf->lcl_bpools_params[k].buff_size);
					if (!pf->lcl_bpools_params[k].buff_size) {
						rc = -EINVAL;
						goto read_cfg_exit2;
					}
				}

				json_buffer_to_input(sec, "nicpf_type", pf->type);
				if (nmp_range_validate(pf->type, NMP_LF_NICPF_T_NONE,
						       NMP_LF_NICPF_T_LAST - 1) != 0) {
					rc = -EINVAL;
					goto read_cfg_exit2;
				}

				if (pf->type != NMP_LF_NICPF_T_PP2_PORT) {
					rc = -EINVAL;
					goto read_cfg_exit2;
				}

				sec = strstr(sec, "port-params-pp2-port");
				if (!sec) {
					ODP_ERR("'port-params-pp2-port' not found\n");
					return -EINVAL;
				}

				pf->port_params.pp2_port.match = pp2_name;
				json_buffer_to_input_str(sec, "match", pf->port_params.pp2_port.match);
				if (!pf->port_params.pp2_port.match) {
					ODP_ERR("'pp2 match' not found\n");
					return -EINVAL;
				}

				json_buffer_to_input(sec, "lcl_num_bpools", pf->port_params.pp2_port.lcl_num_bpools);
				if (nmp_range_validate(pf->port_params.pp2_port.lcl_num_bpools,
						       1, NMP_LF_MAX_NUM_LCL_BPOOLS) != 0)
					return -EINVAL;

				for (k = 0; k < pf->port_params.pp2_port.lcl_num_bpools; k++) {
					struct nmp_lf_bpool_params *lcl_bpools_params =
						&pf->port_params.pp2_port.lcl_bpools_params[k];

					memset(tmp_buf, 0, sizeof(tmp_buf));
					snprintf(tmp_buf, sizeof(tmp_buf), "lcl_bpools_params-%d", k);
					sec = strstr(sec, tmp_buf);
					if (!sec) {
						ODP_ERR("'lcl_bpools_params' not found\n");
						return -EINVAL;
					}

					json_buffer_to_input(sec, "max_num_buffs",
							lcl_bpools_params->max_num_buffs);
					if (nmp_range_validate(pf->port_params.pp2_port.lcl_num_bpools,
							       0, 4096) != 0) {
						return -EINVAL;
					}

					json_buffer_to_input(sec, "buff_size", lcl_bpools_params->buff_size);
					if (nmp_range_validate(lcl_bpools_params->buff_size, 0, 4096) != 0)
						return -EINVAL;
				}
			}
		}

		json_buffer_to_input(sec, "guest_id", params->containers_params[i].guest_id);
		if (nmp_range_validate(params->containers_params[i].guest_id, 0, 10) != 0) {
			rc = -EINVAL;
			goto read_cfg_exit2;
		}
	}

	return 0;
read_cfg_exit2:
	for (i = 0; i < num_lfs; i++)
		kfree(params->containers_params[i].lfs_params);
read_cfg_exit1:
	kfree(params->containers_params);
	return rc;
}

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
