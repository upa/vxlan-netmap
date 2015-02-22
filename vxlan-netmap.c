

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
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "list.h"

#define POLL_TIMEOUT 0
#define NM_BURST_MAX 1024


#define GOLDEN_RATIO_PRIME_32 0x9e370001UL

#define VLAN_VALIDATE(v) (0 <= v && v < 4096)
#define VNI_VALIDATE(v) (0 <= v && v < 0xFFFFFF)

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
#define VXLAN_PORT	4789
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
	int vxlan_port;
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
	int tx_qnum, rx_qnum;
	char * tx_ifname, * rx_ifname;
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

	value &= addr[0];
	value <<= 8;
	value &= addr[1];
	value <<= 8;
	value &= addr[2];
	value <<= 8;
	value &= addr[3];
	value <<= 8;
	value &= addr[4];
	value <<= 8;
	value &= addr[5];
	value <<= 8;
	value &= addr[6];
	value <<= 8;

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

/* netmap util*/

int
extract_netmap_ring (char * ifname, int q, struct netmap_ring ** ring, int x)
{
	int fd;
	char * mem;
	struct nmreq nmr;
	struct netmap_if * nifp;

	/* open netmap for ring */

	fd = open ("/dev/netmap", O_RDWR);
	if (fd < 0) {
		D ("unable to open /dev/netmap");
		return -1;
	}

	memset (&nmr, 0, sizeof (nmr));
	strcpy (nmr.nr_name, ifname);
	nmr.nr_version = NETMAP_API;
	nmr.nr_flags = NETMAP_NO_TX_POLL | NETMAP_DO_RX_POLL;
	nmr.nr_ringid = NETMAP_HW_RING | q;

	if (ioctl (fd, NIOCREGIF, &nmr) < 0) {
		D ("unable to register interface %s", ifname);
		return -1;
	}

	mem = mmap (NULL, nmr.nr_memsize,
		    PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		D ("unable to mmap");
		return -1;
	}

	nifp = NETMAP_IF (mem, nmr.nr_offset);

	if (x > 0)
		*ring = NETMAP_TXRING (nifp, q);
	else
		*ring = NETMAP_RXRING (nifp, q);

	return fd;
}
#define extract_netmap_tx_ring(i, q, r) extract_netmap_ring(i, q, r, 1)
#define extract_netmap_rx_ring(i, q, r) extract_netmap_ring(i, q, r, 0)



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
		D ("dump vni %u, %p, %02x:%02x:%02x:%02x:%02x:%02x",
		   v->vni, f,
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


#define _MACCMP(s, d, n) (s[n] != d[n]) ? 0 :
#define MACCMP(s, d) \
	(_MACCMP(s, d, 0) _MACCMP(s, d, 1) _MACCMP(s, d, 2)	\
	 _MACCMP(s, d, 3) _MACCMP(s, d, 4) _MACCMP(s, d, 5) 1)

struct fdb *
find_fdb (struct list_head * fdb_list, const __u8 * mac)
{
	struct fdb * f;

	list_for_each_entry (f, fdb_head (fdb_list, mac), list) {
		if (MACCMP (f->mac, mac))
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
		if (v->vni == vni)
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

#define mac_copy(s, d) \
	d[0] = s[0]; d[1] = s[1]; d[2] = s[2];	\
	d[3] = s[3]; d[4] = s[4]; d[5] = s[5];	\

void
set_ether_header (struct vxlan_pkt * vpkt, __u8 * dst_mac, __u8 * src_mac)
{
	mac_copy (dst_mac, vpkt->eth.ether_dhost);
	mac_copy (src_mac, vpkt->eth.ether_shost);
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
	if (0)
		ip->ip_sum = wrapsum (checksum (ip, sizeof (*ip), 0));

	return;
}

void
set_udp_header (struct vxlan_pkt * vpkt, size_t len)
{
	struct udphdr * udp;

        udp = &vpkt->udp;

        udp->uh_sport = htons (vxlan.vxlan_port);
        udp->uh_dport = htons (vxlan.vxlan_port);

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
process_ether_to_vxlan (char * src, size_t len, char * pkt)
{
	struct ether_header * eth;
	struct vxlan_pkt * vpkt;
	struct ether_vlan * veth;
	struct vni * v;
	struct fdb * f;
	__u16	vlan;
	__u8 * dst_mac;
	struct in_addr * dst_addr;

	eth = (struct ether_header *) src;

	if (ntohs (eth->ether_type) == ETHERTYPE_VLAN) {
		veth = (struct ether_vlan *) eth;
		vlan = ((ntohs (veth->vlan_tci) << 4) >> 4);
	} else {
		vlan = 0;
	}

	v = vxlan.vlan_table [vlan];
	if (!v) {
		D ("vni instance does not exist in vlan table");
		return;
	}
	
	f = find_fdb (v->fdb_list, eth->ether_dhost);
	if (f) {
		dst_mac = f->vtep_mac;
		dst_addr = (struct in_addr *)&f->vtep;
	} else {
		dst_mac = v->mcast_mac;
		dst_addr = &v->mcast_addr;
	}

	/* xmit encaped packet */

	vpkt = (struct vxlan_pkt *) pkt;
	
	set_ether_header (vpkt, dst_mac, vxlan.src_mac);
	set_ip_header (vpkt, dst_addr, &vxlan.src_addr,
		       len + sizeof (struct ip) + sizeof (struct udphdr) +
		       sizeof (struct vxlanhdr));
	set_udp_header (vpkt, len + sizeof (struct udphdr) +
			sizeof (struct vxlanhdr));
	set_vxlan_header (vpkt, v->vni);

	nm_pkt_copy ((char *)eth, vpkt->body, len);

	return;
}

void *
vxlan_netmap_internal_to_overlay (void * param)
{
	/* receive ethernet frame from internal, and send it with
	   vxlan encap to vxlan overlay networks. */

	int rfd, tfd;
	u_int burst, m, j, k;
	char * epkt, * vpkt;
	struct vxlan_netmap_instance * vnet;
	struct netmap_ring * rxring, * txring;
	struct netmap_slot * rs, * ts;
	struct pollfd x[1];


	rxring = txring = NULL;

	vnet = (struct vxlan_netmap_instance *) param;
	D ("rx %s q %d, tx %s q %d", vnet->rx_ifname, vnet->rx_qnum,
	   vnet->tx_ifname, vnet->tx_qnum);

	rfd = extract_netmap_rx_ring (vnet->rx_ifname, vnet->rx_qnum, &rxring);
	tfd = extract_netmap_tx_ring (vnet->tx_ifname, vnet->tx_qnum, &txring);

	x[0].fd = rfd;
	x[0].events = POLLIN;

	pthread_detach (pthread_self ());

	for (;;) {
		if (poll (x, 1, -1) == 0)
			continue;
		
		j = rxring->cur;
		k = txring->cur;
		burst = NM_BURST_MAX;

		m = nm_ring_space (rxring);
		burst = m < burst ? m : burst;

		m = nm_ring_space (txring);
		burst = m < burst ? m : burst;

		while (burst--) {

			rs = &rxring->slot[j];
			ts = &txring->slot[k];

			epkt = NETMAP_BUF (rxring, rs->buf_idx);
			vpkt = NETMAP_BUF (txring, ts->buf_idx);
			process_ether_to_vxlan (epkt, rs->len, vpkt);
			ts->len = rs->len + VXLAN_HEADROOM;

			j = nm_ring_next (rxring, j);
			k = nm_ring_next (txring, k);
		}

		rxring->head = rxring->cur = j;
		txring->head = txring->cur = k;

		ioctl(tfd, NIOCTXSYNC, NULL);		
	}

	return NULL;
};


void
process_vxlan_to_ether (char * src, size_t len, char * pkt)
{
	__u32 vni;
	struct vni * v;
	struct fdb * f;
	struct vxlan_pkt * vpkt;
	struct ether_vlan * veth;

	vpkt = (struct vxlan_pkt *) src;
	
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

	memcpy (pkt, vpkt->body, len - VXLAN_HEADROOM);

	return;
}

void *
vxlan_netmap_overlay_to_internal (void * param)
{
	/* receive vxlan packet from overlay, decap it, and
	   send to internal network with tagged vlan. */

	int rfd, tfd;
	u_int burst, m, j, k;
	char * epkt, * vpkt;
	struct vxlan_netmap_instance * vnet;
	struct netmap_ring * rxring, * txring;
	struct netmap_slot * rs, * ts;
	struct pollfd x[1];

	rxring = txring = NULL;

	vnet = (struct vxlan_netmap_instance *) param;
	D ("rx %s q %d, tx %s q %d", vnet->rx_ifname, vnet->rx_qnum,
	   vnet->tx_ifname, vnet->tx_qnum);

	rfd = extract_netmap_rx_ring (vnet->rx_ifname, vnet->rx_qnum, &rxring);
	tfd = extract_netmap_tx_ring (vnet->tx_ifname, vnet->tx_qnum, &txring);


	x[0].fd = rfd;
	x[0].events = POLLIN;

	pthread_detach (pthread_self ());

	for (;;) {
		if (poll (x, 1, -1) == 0)
			continue;

		j = rxring->cur;
		k = txring->cur;

		m = nm_ring_space (rxring);
		burst = m < burst ? m : burst;

		m = nm_ring_space (txring);
		burst = m < burst ? m : burst;

		while (burst--) {
			rs = &rxring->slot[j];
			ts = &txring->slot[k];

			vpkt = NETMAP_BUF (rxring, rs->buf_idx);
			epkt = NETMAP_BUF (txring, ts->buf_idx);

			process_vxlan_to_ether (vpkt, rs->len, epkt);
			ts->len = rs->len - VXLAN_HEADROOM;

                        j = nm_ring_next (rxring, j);
			k = nm_ring_next (txring, k);
		}

                rxring->head = rxring->cur = j;
		txring->head = txring->cur = k;

		ioctl(tfd, NIOCTXSYNC, NULL);		
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
	char * args[4] = { NULL, NULL, NULL, NULL };
	struct in_addr mcast_addr;
	struct vni * v;

	for (n = 0; n < strlen (vnivlan) - 1; n++) {
		if (vnivlan[n] == '-') {
			vnivlan[n] = ' ';
		}
	}

	strsplit (vnivlan, args, 4);

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
		"\t -p : vxlan port. defualt 4789\n"
		"\n"
		);

	return;
}

int
main (int argc, char ** argv)
{
	int fd, ov_qnum, in_qnum, n, ch;
	struct nmreq nmr;
	struct vxlan_netmap_instance * vnet;

	memset (&vxlan, 0, sizeof (vxlan));

	INIT_LIST_HEAD (&vxlan.vni_chain);

	for (n = 0; n < VNI_HASH_SIZE; n++)
		INIT_LIST_HEAD (&vxlan.vni_list[n]);

	for (n = 0; n < VLAN_TABLE_SIZE; n++)
		vxlan.vlan_table[n] = NULL;
		
	vxlan.vxlan_port = VXLAN_PORT;

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
			if (vni_vlan_map_init (optarg) < 0)
				return -1;
				
			break;
		case 'p' :
			vxlan.vxlan_port = atoi (optarg);
			break;
		default :
			usage ();
			return -1;
		}
	}

	/* check number of rings */
	
	fd = open ("/dev/netmap", O_RDWR);
	if (fd < 0) {
		D ("Unable to open /dev/netmap");
		perror ("open");
		return -1;
	}

	memset (&nmr, 0, sizeof (nmr));
	nmr.nr_version = NETMAP_API;
	strncpy (nmr.nr_name, vxlan.overlay_ifname, IFNAMSIZ - 1);
	if (ioctl (fd, NIOCGINFO, &nmr) < 0) {
		D ("unabe to get interface info for %s",
		   vxlan.overlay_ifname);
		return -1;
	}
	ov_qnum = nmr.nr_rx_rings;

	memset (&nmr, 0, sizeof (nmr));
	nmr.nr_version = NETMAP_API;
	strncpy (nmr.nr_name, vxlan.internal_ifname, IFNAMSIZ - 1);
	if (ioctl (fd, NIOCGINFO, &nmr) < 0) {
		D ("unabe to get interface info for %s",
		   vxlan.overlay_ifname);
		return -1;
	}
	in_qnum = nmr.nr_rx_rings;
	close (fd);
	
	/* asign threads for rings */

	/* overlay to internal */
	for (n = 0; n < ov_qnum; n++) {
		vnet = (struct vxlan_netmap_instance *) malloc
			(sizeof (struct vxlan_netmap_instance));
		memset (vnet, 0, sizeof (struct vxlan_netmap_instance));

		vnet->rx_ifname = vxlan.overlay_ifname;
		vnet->tx_ifname = vxlan.internal_ifname;
		vnet->rx_qnum = n;
		vnet->tx_qnum = n % in_qnum;

		pthread_create (&vxlan.overlay_t[n], NULL,
				vxlan_netmap_overlay_to_internal, vnet);
	}

	/* internal to overlay*/
	for (n = 0; n < ov_qnum; n++) {
		vnet = (struct vxlan_netmap_instance *) malloc
			(sizeof (struct vxlan_netmap_instance));
		memset (vnet, 0, sizeof (struct vxlan_netmap_instance));

		vnet->rx_ifname = vxlan.internal_ifname;
		vnet->tx_ifname = vxlan.overlay_ifname;
		vnet->rx_qnum = n;
		vnet->tx_qnum = n % ov_qnum;

		pthread_create (&vxlan.internal_t[n], NULL,
				vxlan_netmap_internal_to_overlay, vnet);
	}

	set_if_promisc (vxlan.overlay_ifname);
	set_if_promisc (vxlan.internal_ifname);

	while (1) {
		/* controling vxlan module will be implemented here */
		sleep (1);
	}

	return -1;
}
