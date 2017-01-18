/* Copyright (c) 2017
 */

/* Linux CPU affinity */
#define _GNU_SOURCE

/* Linux PID */
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <odph_debug.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>

#include <odp.h>
#include <odp_api.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
//#include <odp/helper/ip.h>

#define POOL_NUM_PKT 1024
#define POOL_SEG_LEN 1856
/** Maximum number of packet in a burst */
#define MAX_PKT_BURST 1

#define MAX_WORKERS	1
/** Maximum number of pktio interfaces */
#define MAX_PKTIOS	1
#define PKTIN_WAIT_SEC 1000000000
#define SP_DBG(fmt, ...)

static int exit_thr;

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

/**
 * Parsed command line application arguments
 */
typedef struct {
	uint32_t ip_addr[MAX_PKTIOS];   /**< Array of tapX interface ip address */
	char *if_names[MAX_PKTIOS]; /**< Array of pointers to interface names */
	int if_idx[MAX_PKTIOS];
	int if_count;
} app_args_t;

struct {
	app_args_t	cmd_args;
	odp_pktio_t pktio[MAX_PKTIOS];
	odp_pktin_queue_t pktin[MAX_PKTIOS];
	odp_pktout_queue_t pktout[MAX_PKTIOS];
	int fd[MAX_PKTIOS];
	odp_pool_t pool[MAX_PKTIOS];
} global;

static void print_args(app_args_t *args){
	int i;
	struct in_addr addr;
	printf("|Interface|   IP address  |Index|\n");
	for(i=0; i< args->if_count; i++){
		addr.s_addr = args->ip_addr[i];
		printf("|%9s|%15s|%5d|\n",
				args->if_names[i],
				inet_ntoa(addr),
				args->if_idx[i]);
	}
}

static void print_usage(char *progname)
{
	printf("\n"
	       "ODP Slow Path application.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth0,eth1 -a 1.1.1.0,2.2.2.0\n"
	       "  In the above example,\n"
	       "  Traffic incoming from eth0 or eth1 will be passed to Linux Stack for handling\n"
		   "  For each interface a corresponding tap interface will be created to handle the traffic with the provided IP address\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface eth interfaces (comma-separated, no spaces)\n"
		   "                  Interface count min 1, max %i\n"
	       "  -a, --address IP addresses (comma-separated, no spaces)\n"
	       "	Must provide an address for each interface\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -h, --help   Display help and exit.\n\n"
	       "\n", NO_PATH(progname), NO_PATH(progname), MAX_PKTIOS
	    );
}

static void parse_cmdline_args(int argc, char *argv[], app_args_t *args)
{
	int opt;
	int long_index;
	char *token, *local;
	size_t len;
	int i, addr_count = 0;

	static struct option longopts[] = {
			{"interface", required_argument, NULL, 'i'},	/* return 'i' */
			{"address", required_argument, NULL, 'a'},	/* return 'a' */
			{"help", no_argument, NULL, 'h'},		/* return 'h' */
			{NULL, 0, NULL, 0}
	};

	while (1) {
		opt = getopt_long(argc, argv, "+i:a:h",
				longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
			/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				goto out;
			}
			len += 1;	/* add room for '\0' */

			local = malloc(len);
			if (!local) {
				goto mem_fail;
			}

			/* count the number of tokens separated by ',' */
			strcpy(local, optarg);
//			printf("optarg:%s\n", optarg);
			for (token = strtok(local, ","), i = 0;
					token != NULL;
					token = strtok(NULL, ","), i++) {
//				printf("token:%s\n", token);
				if ((i+1) > MAX_PKTIOS) {
					printf("Too many interfaces provided\n");
					free(local);
					goto out;
				}
				args->if_names[i] = token;
				if(sscanf(token,"eth%d", &args->if_idx[i]) == 0){
					printf("Wrong interface provided\n");
					free(local);
					goto out;
				}
			}
//			printf("local:%s, i=%d\n", local, i);
			if (i == 0) {
				printf("No interface provided\n");
				free(local);
				goto out;
			}
			args->if_count = i;
			break;

			/*Configure Route in forwarding database*/
		case 'a':
			len = strlen(optarg);
			if (len == 0) {
				goto out;
			}
			len += 1;	/* add room for '\0' */

			local = malloc(len);
			if (local == NULL) {
				goto mem_fail;
			}

			/* store the mac addresses names */
//			printf("optarg:%s\n",optarg);
			strcpy(local, optarg);
			for (token = strtok(local, ","), i = 0;
					token != NULL; token = strtok(NULL, ","), i++) {
				if (i >= MAX_PKTIOS) {
					printf("too many IP addresses\n");
					free(local);
					goto out;
				}

				if(inet_aton(token, (struct in_addr *)&args->ip_addr[i]) == 0){
					printf("invalid IP address\n");
					free(local);
					goto out;
				}
			}

			if (i == 0) {
				free(local);
				goto out;
			}
			addr_count = i;
			free(local);
			break;

		case 'h':
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}

	/* checking arguments */
	if (args->if_count == 0) {
		printf("\nNo option -i specified.\n");
		goto out;
	}

	if (addr_count == 0) {
		printf("\nNo option -a specified.\n");
		goto out;
	}

	if (addr_count != args->if_count) {
		printf("Number of addresses differs from number"
		       " of interfaces\n");
		goto out;
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
	printf("parse completed\n");
	print_args(args);
	return;

	out:
	print_usage(argv[0]);
	exit(EXIT_FAILURE);
	mem_fail:
	printf("\nAllocate memory failure.\n");
	goto out;

}
static int tap_alloc(char *dev, int flags) {

	struct ifreq ifr;
	int fd, err;
	const char *clonedev = "/dev/net/tun";

	/* Arguments taken by the function:
	 *
	 * char *dev: the name of an interface (or '\0'). MUST have enough
	 *   space to hold the interface name if '\0' is passed
	 * int flags: interface flags (eg, IFF_TUN etc.)
	 */

	/* open the clone device */
	if( (fd = open(clonedev, O_RDWR)) < 0 ) {
		ODPH_ERR("open failed");
		return fd;
	}
	SP_DBG("open fd:%d\n", fd);
	/* preparation of the struct ifr, of type "struct ifreq" */
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;   /* IFF_TUN or IFFemacs_TAP, plus maybe IFF_NO_PI */

	if (*dev) {
		/* if a device name was specified, put it in the structure; otherwise,
		 * the kernel will try to allocate the "next" device of the
		 * specified type */
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	/* try to create the device */
	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
		ODPH_ERR("ioctl failed");
		close(fd);
		return -1;
	}
	//ODPH_DBG("ioctl\n");
	/* if the operation was successful, write back the name of the
	 * interface to the variable "dev", so the caller can know
	 * it. Note that the caller MUST reserve space in *dev (see calling
	 * code below) */
	strcpy(dev, ifr.ifr_name);

	/* Let hardware do checksum */
	ioctl(fd, TUNSETNOCSUM, 1);

	/* DEBUG */
	ioctl(fd, TUNSETDEBUG, 1);


	/* this is the special file descriptor that the caller will use to talk
	 * with the virtual interface */
	return fd;
}


/* Return the fd of the tap */
static int sp_setup_device(char *if_name, char *tap_name, uint32_t addr)
{
	int fd, socket_fd, mtu;
	struct ifreq ifr;
	char str[20];

//	struct sockaddr ip_addr;
//	memset(&ip_addr, 0x0, sizeof(ip_addr));

	/* Create device */
	fd = tap_alloc(tap_name, IFF_TAP  | IFF_NO_PI);
	if (fd < 0) {
		ODPH_ERR("tap_alloc failed");
		return -1;
	}
	socket_fd = socket(PF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0x0, sizeof(ifr));
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(socket_fd, SIOCGIFHWADDR, &ifr) < 0) {
		ODPH_ERR("Failed to get MAC address: %s", strerror(errno));
		close(socket_fd);
		close(fd);
		return -1;
	}

//	hwaddr.sa_family = AF_UNIX;
//	memcpy(hwaddr.sa_data, mac, sizeof(mac));

	/* Set the same MAC address as reported by ODP */
//	memset(&ifr, 0x0, sizeof(ifr));
	strncpy(ifr.ifr_name, tap_name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
//	memcpy(&ifr.ifr_hwaddr, &hwaddr, sizeof(ifr.ifr_hwaddr));

	//ODPH_DBG("Fastpath device %s addr %s",fp_name, ofp_print_mac((uint8_t *)ifr.ifr_hwaddr.sa_data));
	 sprintf(str, "%x:%x:%x:%x:%x:%x", ifr.ifr_hwaddr.sa_data[0], ifr.ifr_hwaddr.sa_data[1], ifr.ifr_hwaddr.sa_data[2],
			 ifr.ifr_hwaddr.sa_data[3], ifr.ifr_hwaddr.sa_data[4], ifr.ifr_hwaddr.sa_data[5]);
	 SP_DBG("ifr_hwaddr: %s\n",str);

	/* Setting HW address of FP kernel representation */
	if (ioctl(fd, SIOCSIFHWADDR, &ifr) < 0) {
		ODPH_ERR("Failed to set MAC address: %s", strerror(errno));
		close(fd);
		close(socket_fd);
		return -1;
	}

#if 0
	/* Get ethX interface IPv4 address */
	memset(&ifr, 0x0, sizeof(ifr));
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(socket_fd, SIOCGIFADDR, &ifr) < 0) {
		ODPH_ERR("Failed to get IPv4 address: %s", strerror(errno));
		close(socket_fd);
		close(fd);
		return -1;
	}

	struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
	printf("IPv4 address: %s\n",inet_ntoa(ipaddr->sin_addr));
	printf("IPv4 address: 0x%x\n",addr);
	printf("address family: %d\n",ifr.ifr_addr.sa_family);
#endif

	/* Set IPv4 address on tapX interface */
	memset(&ifr, 0x0, sizeof(ifr));
	strncpy(ifr.ifr_name, tap_name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	ifr.ifr_addr.sa_family = AF_INET;
	memcpy(&ifr.ifr_addr.sa_data[2],&addr, sizeof(addr));
	if (ioctl(socket_fd, SIOCSIFADDR, &ifr) < 0) {
		ODPH_ERR("Failed to set Ipv4 address: %s", strerror(errno));
		close(fd);
		close(socket_fd);
		return -1;
	}

	/* Get ethX interface MTU */
	memset(&ifr, 0x0, sizeof(ifr));
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(socket_fd, SIOCGIFMTU, &ifr) < 0) {
		ODPH_ERR("Failed to get MTU: %s", strerror(errno));
		close(socket_fd);
		close(fd);
		return -1;
	}

	mtu = ifr.ifr_mtu;
	SP_DBG("%s mtu:%d\n", if_name, mtu);

	/* Set MTU on tapX interface */
	memset(&ifr, 0x0, sizeof(ifr));
	strncpy(ifr.ifr_name, tap_name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	ifr.ifr_mtu = mtu;
	printf("Fastpath device %s MTU %i\n", tap_name, ifr.ifr_mtu);

	if (ioctl(socket_fd, SIOCSIFMTU, &ifr) < 0) {
		ODPH_ERR("Failed to set MTU: %s", strerror(errno));
		close(socket_fd);
		close(fd);
		return -1;
	}

	/* Get flags */
	memset(&ifr, 0x0, sizeof(ifr));
	strncpy(ifr.ifr_name, tap_name, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(socket_fd, SIOCGIFFLAGS, &ifr) < 0) {
		ODPH_ERR("Failed to get interface flags: %s", strerror(errno));
		close(socket_fd);
		close(fd);
		return -1;
	}

	/* Set flags - ifconfig up*/
	if (!(ifr.ifr_flags & IFF_UP)) {
		/* ifconfig up */
		ifr.ifr_flags |= IFF_UP;
		if (ioctl(socket_fd, SIOCSIFFLAGS, &ifr) < 0) {
			ODPH_ERR("Failed to set interface flags: %s",
					strerror(errno));
			close(socket_fd);
			close(fd);
			return -1;
		}
	}

	close(socket_fd);
	return fd;
}


static void sig_handler(int signo ODP_UNUSED)
{
	int ifx;
	printf("sig_handler!\n");
	for(ifx=0; ifx < global.cmd_args.if_count;ifx++){
		close(global.fd[ifx]);
	}
	exit_thr = 1;
}

static odp_pktio_t create_pktio(const char *name, odp_pool_t pool,
				odp_pktin_queue_t *pktin,
				odp_pktout_queue_t *pktout)
{
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t in_queue_param;
	odp_pktout_queue_param_t out_queue_param;
	odp_pktio_t pktio;

	odp_pktio_param_init(&pktio_param);

	pktio = odp_pktio_open(name, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		ODPH_DBG("Failed to open %s\n", name);
		exit(1);
	}

	odp_pktin_queue_param_init(&in_queue_param);
	odp_pktout_queue_param_init(&out_queue_param);

	in_queue_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;

	if (odp_pktin_queue_config(pktio, &in_queue_param)) {
		ODPH_DBG("Failed to config input queue for %s\n", name);
		exit(1);
	}

	out_queue_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;

	if (odp_pktout_queue_config(pktio, &out_queue_param)) {
		ODPH_DBG("Failed to config output queue for %s\n", name);
		exit(1);
	}

	if (odp_pktin_queue(pktio, pktin, 1) != 1) {
		ODPH_DBG("pktin queue query failed for %s\n", name);
		exit(1);
	}
	if (odp_pktout_queue(pktio, pktout, 1) != 1) {
		ODPH_DBG("pktout queue query failed for %s\n", name);
		exit(1);
	}
	return pktio;
}

static int run_worker_rx(void *arg ODP_UNUSED)
{
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	int pkts, i, len;

	printf("started rx worker thread\n");


	SP_DBG("go into receive loop\n");
	while (!exit_thr) {
		//				ODPH_DBG("wait for rx packet\n");
		pkts = odp_pktin_recv_tmo(global.pktin[0], pkt_tbl, MAX_PKT_BURST,
				odp_pktin_wait_time(PKTIN_WAIT_SEC));

		if (odp_unlikely(pkts <= 0))
			continue;
		SP_DBG("received %d packets\n", pkts);
		for (i = 0; i < pkts; i++) {
			odp_packet_t pkt = pkt_tbl[i];

			if (odp_unlikely(!odp_packet_has_eth(pkt))) {
				ODPH_DBG("warning: packet has no eth header\n");
				return 0;
			}
			//			ODPH_DBG("rx:\n");
			//			odp_packet_print(pkt);
			len = write(global.fd[0],
					(void *)odp_packet_l2_ptr(pkt, NULL),
					(size_t)odp_packet_len(pkt));
			if(len == -1){
				ODPH_DBG("write() failed, %s\n", strerror(errno));
			}else{
				SP_DBG("write %d Bytes\n",len);
			}
			odp_packet_free(pkt);

		}
	}
	ODPH_DBG("worker Rx thread exiting\n");

	return 0;
}



static int run_worker_tx(void *arg ODP_UNUSED)
{
	odp_packet_t pkt;
	int sent, len, r;
	uint8_t *buf_pnt;
	fd_set read_fd;
	struct timeval timeout;

	printf("started tx worker thread\n");

	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	FD_ZERO(&read_fd);

	while (!exit_thr) {

		pkt = odp_packet_alloc(global.pool[0],
				1500 + ODPH_ETHHDR_LEN+
				ODPH_VLANHDR_LEN);

		if (pkt == ODP_PACKET_INVALID) {
			ODPH_ERR("odp_packet_alloc failed");
			usleep(1000);
			continue;
		}

		buf_pnt = odp_packet_data(pkt);

		drop_pkg:
		FD_SET(global.fd[0], &read_fd);
		r = select(global.fd[0]+ 1, &read_fd, NULL, NULL, &timeout);
		if (exit_thr) {
			odp_packet_free(pkt);
			break;
		}
		if (r <= 0)
			goto drop_pkg;

		len = read(global.fd[0], buf_pnt, odp_packet_len(pkt));
		SP_DBG("read %d Bytes, ",len);
		if (len <= 0) {
			ODPH_ERR("read failed");
			odp_packet_free(pkt);
			if (exit_thr) {
				break;
			}
			goto drop_pkg;
		}

		/* len > 0 */
		odp_packet_reset(pkt, (size_t)len);
		odp_packet_l2_offset_set(pkt, 0);
		//				odp_packet_print(pkt);
		/* Send the packet to fastpath device */
		sent = odp_pktout_send(global.pktout[0], &pkt, 1);
		SP_DBG("sent:%d\n",sent);
		if(sent<=0){
			odp_packet_free(pkt);
			ODPH_ERR("odp_pktout_send failed");
			continue;
		}
	}

	printf("worker Tx thread exiting\n");

	return 0;
}

int main(int argc, char **argv)
{
	odp_pool_param_t params;
	odp_cpumask_t cpumask;
	odph_odpthread_t thd_tbl[2];
	odp_instance_t instance;
	odph_odpthread_params_t thr_params;
	int  ifx;
	char if_name[IFNAMSIZ];
	app_args_t *args;

	args = &global.cmd_args;
	parse_cmdline_args(argc, argv, args);

	if (odp_init_global(&instance, NULL, NULL)) {
		ODPH_DBG("Error: ODP global init failed.\n");
		exit(1);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_DBG("Error: ODP local init failed.\n");
		exit(1);
	}

	/* Create packet pool, currently only one */
	odp_pool_param_init(&params);
	params.pkt.seg_len = POOL_SEG_LEN;
	params.pkt.len     = POOL_SEG_LEN;
	params.pkt.num     = POOL_NUM_PKT;
	params.type        = ODP_POOL_PACKET;

//	snprintf(pool_name, 14, "packet pool %d", ifx);

	/* TODO: MUSDK only supports pool name "packet pool" */
	global.pool[0] = odp_pool_create("packet pool", &params);
	if (global.pool[0] == ODP_POOL_INVALID) {
		ODPH_DBG("Error: packet pool create failed.\n");
		exit(1);
	}

	for(ifx=0; ifx < args->if_count;ifx++){

		printf("create pktio on interface %s\n", args->if_names[ifx]);
		global.pktio[ifx] = create_pktio(args->if_names[ifx], global.pool[ifx], &global.pktin[ifx],
				&global.pktout[ifx]);

		/* Prepare tap device name*/
		snprintf(if_name, IFNAMSIZ, "tap%d", args->if_idx[ifx]);
		if_name[IFNAMSIZ - 1] = 0;
		printf("if_name:%s ifx:%d\n",if_name, ifx);
		/* Create device */
		global.fd[ifx] = sp_setup_device(args->if_names[ifx], if_name,args->ip_addr[ifx]);
		if (global.fd[ifx] < 0) {
			ODPH_ERR("setup tap device failed");
			return -1;
		}

		if (odp_pktio_start(global.pktio[ifx])) {
			printf("unable to start input interface\n");
			exit(1);
		}
	}
	odp_cpumask_default_worker(&cpumask, MAX_WORKERS);

	signal(SIGINT, sig_handler);

	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.start    = run_worker_rx;
	thr_params.arg      = NULL;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;
	odph_odpthreads_create(&thd_tbl[0], &cpumask, &thr_params);

	sleep(2);
	thr_params.start    = run_worker_tx;
	odph_odpthreads_create(&thd_tbl[1], &cpumask, &thr_params);

	odph_odpthreads_join(thd_tbl);

	/* if_names share a single buffer, so only one free */
	free(global.cmd_args.if_names[0]);

	for(ifx=0; ifx < args->if_count;ifx++){
		if (odp_pool_destroy(global.pool[ifx])) {
			ODPH_DBG("Error: pool destroy\n");
			exit(EXIT_FAILURE);
		}
	}
	if (odp_term_local()) {
		ODPH_DBG("Error: term local\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_DBG("Error: term global\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
