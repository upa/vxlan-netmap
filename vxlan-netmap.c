

#include <errno.h>
#include <unistd.h>    
#include <stdio.h>
#include <stdlib.h>
#include <string.h>    
#include <inttypes.h>  
#include <fcntl.h>     
#include <sys/mman.h>  
#include <sys/ioctl.h> 
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/time.h> 
#include <net/ethernet.h>
#include <net/if.h>   
#include <ifaddrs.h>   
#include <arpa/inet.h> 
#include <asm-generic/int-ll64.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <net/netmap.h>
#include <net/netmap_user.h>

#include "list.h"

/* from nm_util.h */
#define D(format, ...)					\
        fprintf(stderr, "%s [%d] " format "\n",         \
		__FUNCTION__, __LINE__, ##__VA_ARGS__)


#define GOLDEN_RATIO_PRIME_32 0x9e370001UL

#define VLAN_VALIDATE(v) (0 < v && v < 4096)
#define VNI_VALIDATE(v) (0 < v && v < 0xFFFFFF)


struct ether_vlan {
	__u8	ether_dhost[ETH_ALEN];
	__u8	ether_shost[ETH_ALEN];
	__u16	vlan_tpid;
	__u16	vlan_tci;
	__u16	ether_type;
} __attribute__ ((__packed__));


/* from kernel driver */
struct vxlanhdr {
	__u32	vx_flags;
	__u32	vx_vni;
} __attribute__ ((__packed__));
#define VXLAN_FLAGS	0x08000000
#define VXLAN_PORT	8472
#define VXLAN_HEADROOM (sizeof (struct ether_header) + sizeof (struct ip) \
			+ sizeof (struct udphdr) + sizeof (struct vxlanhdr))

struct vxlan_pkt {
	struct ether_header eth;
	struct ip ip;
	struct udphdr udp;
	struct vxlanhdr vxlan;
	char body[1];
} __attribute__ ((__packed__));


#define FDB_HASH_BITS	8
#define VNI_HASH_BITS	8
#define FDB_HASH_SIZE	(1 << FDB_HASH_BITS)
#define VNI_HASH_SIZE	(1 << VNI_HASH_BITS)

#define VLAN_TABLE_SIZE	4095	/* koreha hidoi..., */

struct fdb {
	struct list_head list;
	struct list_head chain;	

	pthread_mutex_t	mutex;

	__u8	mac[ETH_ALEN], vtep_mac[ETH_ALEN];
	struct in_addr vtep;

	int family;

	int	lifetime;
	struct timeval update;
};
#define VXLAN_FDB_LIFETIME	180
#define VXLAN_AGING_INTERVAL	10


/* in this implementation, vni is mapped to 1 vlan id */
struct vni {
	__u32	vni;
	__u16	vlan;

	struct list_head	list;	/* for hash table */
	struct list_head	chain;	/* for list chain */

	struct list_head	fdb_list[FDB_HASH_SIZE];
	struct list_head	fdb_chain;

	struct in_addr	mcast_addr;
	__u8	mcast_mac[ETH_ALEN];

	pthread_t	age_t;	/* aging fdb thread */
};


/* vxlan process instance */

#define VXLAN_THREAD_MAX	16

struct vxlan {
	int fd;
	char * overlay_ifname, * internal_ifname;
	
	struct list_head	vni_list[VNI_HASH_SIZE];
	struct list_head	vni_chain;

	pthread_t	overlay_t[VXLAN_THREAD_MAX];
	pthread_t	internal_t[VXLAN_THREAD_MAX];

	struct vni * vlan_table[VLAN_TABLE_SIZE];

	struct in_addr src_addr;
	struct in_addr gateway_addr;
	__u8	src_mac[ETH_ALEN];
};

struct vxlan vxlan;

struct vxlan_netmap_instance {
	int rx_fd, tx_fd;
	struct netmap_ring * txring, * rxring;
};


#ifdef __linux__
#define uh_sport source
#define uh_dport dest
#define uh_ulen len
#define uh_sum check
#endif /* linux */

/* utils */

int
set_if_promisc (char * ifname)
{
	int fd;
	struct ifreq ifr;

	fd = socket (AF_INET, SOCK_DGRAM, 0);
	memset (&ifr, 0, sizeof (ifr));
	strncpy (ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl (fd, SIOCGIFFLAGS, &ifr) != 0) {
		D ("failed to get interface status");
		return -1;
	}

	ifr.ifr_flags |= IFF_UP|IFF_PROMISC;

	if (ioctl (fd, SIOCSIFFLAGS, &ifr) != 0) {
		D ("failed to set interface to promisc");
		return -1;
	}

	return 0;
}

int
get_if_mac (char * ifname, __u8 * mac)
{
	int fd;
	struct ifreq ifr;

	fd = socket (AF_INET, SOCK_DGRAM, 0);
	memset (&ifr, 0, sizeof (ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy (ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl (fd, SIOCGIFHWADDR, &ifr) < 0) {
		D ("failed to get mac addr of %s", ifname);
		perror ("ioctl");
		return -1;
	}

	close (fd);

	memcpy (mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	return 0;
}

/* from linux kernel */

static inline 
__u32 hash_32(__u32 val, unsigned int bits)
{
	/* On some cpus multiply is faster, on others gcc will do shifts */
	__u32 hash = val * GOLDEN_RATIO_PRIME_32;

	/* High bits are more random, so use them. */
	return hash >> (32 - bits);
}

static inline 
__u64 hash_64(__u64 val, unsigned int bits)
{
	__u64 hash = val;

	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	__u64 n = hash;
	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;

	/* High bits are more random, so use them. */
	return hash >> (64 - bits);
}


static __u32 
eth_hash(const __u8 * addr)
{
	/* from vxlan.c */

	__u64 value = 0;

	memcpy (&value, addr, ETH_ALEN);

	/* only want 6 bytes */
#ifdef __BIG_ENDIAN
	value >>= 16;
#else
	value <<= 16;
#endif

	return hash_64(value, FDB_HASH_BITS);
}


/* from netmap pkt-gen.c */

static uint16_t
checksum(const void * data, uint16_t len, uint32_t sum)
{
        const uint8_t *addr = data;
        uint32_t i;

        /* Checksum all the pairs of bytes first... */
        for (i = 0; i < (len & ~1U); i += 2) {
                sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }
        /*
         * If there's a single byte left over, checksum it, too.
         * Network byte order is big-endian, so the remaining byte is
         * the high byte.
         */

        if (i < len) {
                sum += addr[i] << 8;
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }

        return sum;
}

static u_int16_t
wrapsum(u_int32_t sum)
{
        sum = ~sum & 0xFFFF;
        return (htons(sum));
}


/****  FDB  *****/

inline struct list_head *
fdb_head (struct list_head * fdb_list, const __u8 * mac)
{
	return &fdb_list[eth_hash (mac)];
}


void
dump_fdb (struct vni * v)
{
	struct fdb * f;

	list_for_each_entry (f, &v->fdb_chain, chain) {
		D ("dump vni %u, %p, %02x:%02x:%02x:%02x:%02x:%02x", v->vni,
		   f,
		   f->mac[0], f->mac[1],
		   f->mac[2], f->mac[3],
		   f->mac[4], f->mac[5]);
	}

	return;
}

void
dump_fdb2 (struct vni * v)
{
	int n;
	struct fdb * f;
	for (n = 0; n < FDB_HASH_SIZE; n++) {
		list_for_each_entry (f, &v->fdb_list[n], list) {
			D ("dump vni %u,n is %d, %p, "
			   "%02x:%02x:%02x:%02x:%02x:%02x", 
			   v->vni, n, f,
			   f->mac[0], f->mac[1],
			   f->mac[2], f->mac[3],
			   f->mac[4], f->mac[5]);
		}
	}

	return;
}

struct fdb *
find_fdb (struct list_head * fdb_list, const __u8 * mac) 
{
	struct fdb * f;

	list_for_each_entry (f, fdb_head (fdb_list, mac), list) {
		if (memcmp (f->mac, mac, ETH_ALEN) == 0) 
			return f;
	}

	return NULL;
}

struct fdb *
create_fdb (const __u8 * mac, struct in_addr * vtep, const __u8 * vtep_mac)
{
	struct fdb * f;

	f = (struct fdb *) malloc (sizeof (struct fdb));
	memset (f, 0, sizeof (struct fdb));

	memcpy (f->mac, mac, ETH_ALEN);
	memcpy (f->vtep_mac, vtep_mac, ETH_ALEN);
	memcpy (&f->vtep, vtep, sizeof (struct in_addr));
	pthread_mutex_init (&f->mutex, NULL);

	f->lifetime = VXLAN_FDB_LIFETIME;

	gettimeofday (&f->update, NULL);

	return f;
}

void
add_fdb (struct vni * v, struct fdb * f)
{
	D ("add mac %02x:%02x:%02x:%02x:%02x:%02x to VNI %u",
	   f->mac[0], f->mac[1], f->mac[2], f->mac[3], f->mac[4], f->mac[5],
	   v->vni);

	list_add (&f->chain, &v->fdb_chain);
	list_add (&f->list, fdb_head (v->fdb_list, f->mac));

	return;
}

void
del_fdb (struct fdb * f)
{
	list_del (&f->list);
	list_del (&f->chain);

	return;
}

/****  VNI  ****/

inline struct list_head *
vni_head (struct list_head * vni_list, __u32 vni)
{
	return &vni_list[hash_32 (vni, VNI_HASH_BITS)];
}

struct vni *
find_vni (struct list_head * vni_list, __u32 vni)
{
	struct vni * v;

	list_for_each_entry (v, vni_head (vni_list, vni), list) {
		if (memcmp (&v->vni, &vni, sizeof (vni)) == 0)
			return v;
	}

	return NULL;
}

void
add_vni (struct list_head * vni_list, struct vni * v)
{
	list_add (&v->list, vni_head (vni_list, v->vni));
	list_add (&v->chain, &vxlan.vni_chain);

	return;
}

void *
aging_fdb_thread (void * param)
{
	struct fdb * f;
	struct list_head * p, * tmp;
	struct vni * v = (struct vni *) param;

	pthread_detach (pthread_self ());

	for (;;) {
		list_for_each_safe (p, tmp, &v->fdb_chain) {
			f = list_entry (p, struct fdb, chain);
			f->lifetime -= VXLAN_AGING_INTERVAL;

			if (f->lifetime < 0) {
				del_fdb (f);
			}
		}

		sleep (VXLAN_AGING_INTERVAL);
	}

	/* not reached */

	return NULL;
}

struct vni *
create_vni (__u32 vni, __u16 vlan, struct in_addr mcast_addr) 
{
	int n;
	struct vni * v;


	v = (struct vni *) malloc (sizeof (struct vni));
	memset (v, 0, sizeof (struct vni));

	v->vni = vni;
	v->vlan = vlan;

	INIT_LIST_HEAD (&v->fdb_chain);
	for (n = 0; n < FDB_HASH_SIZE; n++) 
		INIT_LIST_HEAD (&v->fdb_list[n]);

	v->mcast_addr = mcast_addr;
	memcpy (v->mcast_mac + 2, &v->mcast_addr, sizeof (mcast_addr));
	v->mcast_mac[0] = 0x01;
	v->mcast_mac[1] = 0x00;
	v->mcast_mac[2] = 0x5E;
	v->mcast_mac[3] = (v->mcast_mac[3] << 1) >> 1;

	/* init aging thread */

	pthread_create (&v->age_t, NULL, aging_fdb_thread, v);

	return v;
}


/****  setup headers ****/

void
set_ether_header (struct vxlan_pkt * vpkt, __u8 * dst_mac, __u8 * src_mac)
{
	memcpy (vpkt->eth.ether_dhost, dst_mac, ETH_ALEN);
	memcpy (vpkt->eth.ether_shost, src_mac, ETH_ALEN);
	vpkt->eth.ether_type = htons (ETHERTYPE_IP);

	return;
}

void
set_ip_header (struct vxlan_pkt * vpkt, struct in_addr * dst_addr, 
	       struct in_addr * src_addr, size_t len)
{

	struct ip * ip;
	ip = &vpkt->ip;

	ip->ip_v = IPVERSION;
        ip->ip_hl = 5;
        ip->ip_id = 0;
        ip->ip_tos = IPTOS_LOWDELAY;
        ip->ip_len = ntohs (len);
	ip->ip_id = 0;
        ip->ip_off = htons (IP_DF);
        ip->ip_ttl = 16;
        ip->ip_p = IPPROTO_UDP;
        ip->ip_dst = *dst_addr;
        ip->ip_src = *src_addr;
	ip->ip_sum = 0;
        ip->ip_sum = wrapsum (checksum (ip, sizeof (*ip), 0));

	return;
}

void
set_udp_header (struct vxlan_pkt * vpkt, size_t len)
{
	struct udphdr * udp;

        udp = &vpkt->udp;

        udp->uh_sport = htons (VXLAN_PORT);
        udp->uh_dport = htons (VXLAN_PORT);

        udp->uh_ulen = htons (len);

        udp->uh_sum = 0;        /* no udp checksum */

	return;
}

void
set_vxlan_header (struct vxlan_pkt * vpkt, __u32 vni)
{
	struct vxlanhdr * vhdr;

	vhdr = &vpkt->vxlan;

	vhdr->vx_flags = htonl (VXLAN_FLAGS);
	vhdr->vx_vni = htonl (vni << 8);

	return;
}

/****  forwarding instance  ****/

void
process_ether_to_vxlan (struct ether_header * eth, size_t len,
			struct netmap_ring * txring, int tx_fd)
{
	u_int cur;
	struct vxlan_pkt * vpkt;
	struct ether_vlan * veth;
	struct vni * v;
	struct fdb * f;
	__u16	vlan;
	__u8 * dst_mac;
	struct in_addr * dst_addr;
	struct netmap_slot * slot;

	if (ntohs (eth->ether_type) != ETHERTYPE_VLAN) {
		D ("packet is not tagged vlan frame, %x",
		   ntohs (eth->ether_type));
		return;
	}

	veth = (struct ether_vlan *) eth;
	vlan = ((ntohs (veth->vlan_tci) << 4) >> 4); 
	
	v = vxlan.vlan_table [vlan];
	if (!v) {
		D ("vni instance does not exist in vlan table");
		return;
	}
	
	f = find_fdb (v->fdb_list, veth->ether_dhost);
	if (f) {
		dst_mac = f->vtep_mac;
		dst_addr = (struct in_addr *)&f->vtep;
	} else {
		dst_mac = v->mcast_mac;
		dst_addr = &v->mcast_addr;
	}

	/* xmit encaped packet */
	
	if (txring->avail == 0) {
		while (!NETMAP_TX_RING_EMPTY (txring)) {
			ioctl (tx_fd, NIOCTXSYNC, NULL);
			usleep (1);
		}
	}

	cur = txring->cur;
	slot = &txring->slot[cur];
	vpkt = (struct vxlan_pkt *) NETMAP_BUF (txring, slot->buf_idx);
	
	set_ether_header (vpkt, dst_mac, vxlan.src_mac);
	set_ip_header (vpkt, dst_addr, &vxlan.src_addr,
		       len + sizeof (struct ip) + sizeof (struct udphdr) +
		       sizeof (struct vxlanhdr));
	set_udp_header (vpkt, len + sizeof (struct udphdr) +
			sizeof (struct vxlanhdr));
	set_vxlan_header (vpkt, v->vni);

	memcpy (vpkt->body, eth, len);
	slot->len = len + VXLAN_HEADROOM;
	cur = NETMAP_RING_NEXT (txring, cur);
	
	txring->avail -= 1;
	txring->cur = cur;

	return;
}

void *
vxlan_netmap_internal_to_overlay (void * param)
{
	/* receive ethernet frame from internal, and send it with 
	   vxlan encap to vxlan overlay networks. */

	u_int cur;
	struct ether_header * eth;
	struct vxlan_netmap_instance * vnet;
	struct netmap_ring * rxring, * txring;
	struct netmap_slot * slot;

	struct pollfd x[1];

	vnet = (struct vxlan_netmap_instance *) param;
	rxring = vnet->rxring;
	txring = vnet->txring;

	pthread_detach (pthread_self ());

	D ("rx ring is %p tx is %p", rxring, txring);

	x[0].fd = vnet->rx_fd;
	x[0].events = POLLIN;

	for (;;) {
		poll (x, 1, 100);
		
		for (; rxring->avail > 0; rxring->avail--) {

			cur = rxring->cur;
			slot = &rxring->slot[cur];
			eth = (struct ether_header *) 
				NETMAP_BUF (rxring, slot->buf_idx);

			process_ether_to_vxlan (eth, slot->len, txring,
						vnet->tx_fd);
			rxring->cur = NETMAP_RING_NEXT (rxring, cur);
			ioctl(vnet->tx_fd, NIOCTXSYNC, NULL);
		}
	}

	return NULL;
};


void
process_vxlan_to_ether (struct vxlan_pkt * vpkt, size_t len,
			struct netmap_ring * txring, int tx_fd)
{
	__u32 vni;
	u_int cur;
	char * pkt;
	struct vni * v;
	struct fdb * f;
	struct ether_vlan * veth;
	struct netmap_slot * slot;

	vni = ntohl (vpkt->vxlan.vx_vni) >> 8;
	v = find_vni (vxlan.vni_list, vni);
	if (!v) {
		D ("vni %u does not exist", vni);
		return;
	}

	veth = (struct ether_vlan *) vpkt->body;

	f = find_fdb (v->fdb_list, veth->ether_shost);
	if (f) {
		memcpy (&f->vtep, &vpkt->ip.ip_src, sizeof (struct in_addr));
		f->lifetime = VXLAN_FDB_LIFETIME;
	} else {
		f = create_fdb (veth->ether_shost, &vpkt->ip.ip_src,
				vpkt->eth.ether_shost);
		add_fdb (v, f);
	}

	/* xmit decaped packet */
	if (txring->avail == 0) {
		while (!NETMAP_TX_RING_EMPTY (txring)) {
			ioctl (tx_fd, NIOCTXSYNC, NULL);
			usleep (1);
		}
	}

	cur = txring->cur;
	slot = &txring->slot[cur];
	pkt = NETMAP_BUF (txring, slot->buf_idx);

	memcpy (pkt, vpkt->body, len - VXLAN_HEADROOM);
	slot->len = len - VXLAN_HEADROOM;
	cur = NETMAP_RING_NEXT (txring, cur);

	txring->avail -= 1;
	txring->cur = cur;

	return;
}

void *
vxlan_netmap_overlay_to_internal (void * param)
{
	/* receive vxlan packet from overlay, decap it, and 
	   send to internal network with tagged vlan. */

	u_int cur;
	struct vxlan_pkt * vpkt;
	struct vxlan_netmap_instance * vnet;
	struct netmap_ring * rxring, * txring;
	struct netmap_slot * slot;

	struct pollfd x[1];

	vnet = (struct vxlan_netmap_instance *) param;
	rxring = vnet->rxring;
	txring = vnet->txring;

	pthread_detach (pthread_self ());
	
	x[0].fd = vnet->rx_fd;
	x[0].events = POLLIN;

	D ("rx ring is %p tx is %p", rxring, txring);

	for (;;) {
		poll (x, 1, 100);

		for (; rxring->avail > 0; rxring->avail--) {
			
			cur = rxring->cur;
			slot = &rxring->slot[cur];
			vpkt = (struct vxlan_pkt *) 
				NETMAP_BUF (rxring, slot->buf_idx);

			process_vxlan_to_ether (vpkt, slot->len, txring, 
						vnet->tx_fd);
			cur = NETMAP_RING_NEXT (rxring, cur);
			rxring->cur = cur;
			ioctl(vnet->tx_fd, NIOCTXSYNC, NULL);
		}
	}

	return NULL;
}

int
strsplit (char * str, char ** args, int max)
{
        int argc;
        char * c;

        for (argc = 0, c = str; *c == ' '; c++);
        while (*c && argc < max) {
                args[argc++] = c;
                while (*c && *c > ' ') c++;
                while (*c && *c <= ' ') *c++ = '\0';
        }

        return argc;
}


int
vni_vlan_map_init (char * vnivlan)
{
	/* vnivlan is "vni-vlan-mcastaddr" */

	int n, vlan, vni;
	char * args[3];
	struct in_addr mcast_addr;
	struct vni * v;

	for (n = 0; n < strlen (vnivlan) - 1; n++) {
		if (vnivlan[n] == '-') {
			vnivlan[n] = ' ';
		}
	}

	strsplit (vnivlan, args, 3);

	vni = atoi (args[0]);
	vlan = atoi (args[1]);
	if (inet_pton (AF_INET, args[2], &mcast_addr) < 1) {
		D ("invalid mcast address %s", args[2]);
		return -1;
	}

	if (!VNI_VALIDATE (vni)) {
		D ("invalid vxlan id %s", args[0]);
		return -1;
	}

	if (!VLAN_VALIDATE (vlan)) {
		D ("invalid vlan id %s", args[1]);
		return -1;
	}
	

	v = create_vni (vni, vlan, mcast_addr);
	
	add_vni (vxlan.vni_list, v);
	vxlan.vlan_table[vlan] = v;

	D ("create vni-vlan mapping, vni=%s, vlan=%s, mcast=%s",
	   args[0], args[1], args[2]);

	return 1;
}

void
usage (void)
{
	printf ("usage of vxlan-netmap\n"
		"\t -o : overlay interface name\n"
		"\t -i : internal interface name\n"
		"\t -s : source vtep address\n"
		"\t -v : vni-vlan-mcastaddr mapping\n"
		"\n"
		);

	return;
}

int
main (int argc, char ** argv)
{
	int ov_fd, in_fd, n, ch;
	char * ovmem, * inmem;
	struct nmreq ovreq, inreq;
	struct vxlan_netmap_instance * vnet;
	struct netmap_if * ov_nifp, * in_nifp;

	memset (&vxlan, 0, sizeof (vxlan));

	INIT_LIST_HEAD (&vxlan.vni_chain);

	for (n = 0; n < VNI_HASH_SIZE; n++) 
		INIT_LIST_HEAD (&vxlan.vni_list[n]);

	for (n = 0; n < VLAN_TABLE_SIZE; n++) 
		vxlan.vlan_table[n] = NULL;
		

	while ((ch = getopt (argc, argv, "o:i:s:v:")) != -1) {

		switch (ch) {
		case 'o' :
			vxlan.overlay_ifname = optarg;
			break;
		case 'i' :
			vxlan.internal_ifname = optarg;
			if (get_if_mac (optarg, vxlan.src_mac) < 0) 
				return -1;
			break;
		case 's' :
			if (inet_pton (AF_INET, optarg, &vxlan.src_addr) < 1) {
				perror ("inet_ptn");
				return -1;
			}
			break;
		case 'v' :
			vni_vlan_map_init (optarg);
			break;
		default :
			usage ();
			return -1;
		}
	}

	
	/* register overlay interface to netmap */
	ov_fd = open ("/dev/netmap", O_RDWR);
	if (ov_fd < 0) {
		D ("unable to open /dev/netmap");
		return -1;
	}

	memset (&ovreq, 0, sizeof (ovreq));
	ovreq.nr_version = NETMAP_API;
	strcpy (ovreq.nr_name, vxlan.overlay_ifname);

	if (ioctl (ov_fd, NIOCREGIF, &ovreq) < 0) {
		D ("unable to register overlay interface");
		return -1;
	}

	ovmem = mmap (NULL, ovreq.nr_memsize,
		      PROT_READ|PROT_WRITE, MAP_SHARED, ov_fd, 0);
	if (ovmem == MAP_FAILED) {
		D ("unable to mmap");
		return -1;
	}

	ov_nifp = NETMAP_IF (ovmem, ovreq.nr_offset);


	/* regsiter internal interface to netmap */

	in_fd = open ("/dev/netmap", O_RDWR);
	if (in_fd < 0) {
		D ("unable to open /dev/netmap");
		return -1;
	}

	memset (&inreq, 0, sizeof (inreq));
	inreq.nr_version = NETMAP_API;
	strcpy (inreq.nr_name, vxlan.internal_ifname);

	if (ioctl (in_fd, NIOCREGIF, &inreq) < 0) {
		D ("unable to register internal interface");
		return -1;
	}

	inmem = mmap (NULL, inreq.nr_memsize,
		      PROT_READ|PROT_WRITE, MAP_SHARED, in_fd, 0);
	if (inmem == MAP_FAILED) {
		D ("unable to mmap");
		return -1;
	}

	in_nifp = NETMAP_IF (inmem, inreq.nr_offset);

	

	/* asign threads for threads */

	if (set_if_promisc (vxlan.overlay_ifname) < 0) 
		return -1;

	if (set_if_promisc (vxlan.internal_ifname) < 0)
		return -1;

	/* overlay -> internal */
	for (n = 0; n < ovreq.nr_rx_rings; n++) {
		vnet = (struct vxlan_netmap_instance *) malloc 
			(sizeof (struct vxlan_netmap_instance));
		memset (vnet, 0, sizeof (struct vxlan_netmap_instance));

		vnet->rx_fd = ov_fd;
		vnet->tx_fd = in_fd;
		vnet->rxring = NETMAP_RXRING (ov_nifp, n);
		vnet->txring = NETMAP_TXRING (in_nifp, n % inreq.nr_tx_rings);

		pthread_create (&vxlan.overlay_t[n], NULL, 
				vxlan_netmap_overlay_to_internal, vnet);
	}

	/* internal -> overlay */
	for (n = 0; n < inreq.nr_rx_rings; n++) {
		vnet = (struct vxlan_netmap_instance *) malloc 
			(sizeof (struct vxlan_netmap_instance));
		memset (vnet, 0, sizeof (struct vxlan_netmap_instance));

		vnet->rx_fd = in_fd;
		vnet->tx_fd = ov_fd;
		vnet->rxring = NETMAP_RXRING (in_nifp, n);
		vnet->txring = NETMAP_TXRING (ov_nifp, n % ovreq.nr_tx_rings);

		pthread_create (&vxlan.internal_t[n], NULL, 
				vxlan_netmap_internal_to_overlay, vnet);
	}


	while (1) {
		sleep (1);
	}

	return -1;
}
