#ifndef _REFLECT_HTTP_CAP_H_
#define _REFLECT_HTTP_CAP_H_

#define _GNU_SOURCE
#include <pcap.h>
#include <sys/socket.h>
#include "packet.h"
#define obstack_chunk_alloc xmalloc
#define obstack_chunk_free free

struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			uint32_t ip6_un1_flow;	/* 4 bits version, 8 bits TC,
						   20 bits flow-ID */
			uint16_t ip6_un1_plen;	/* payload length */
			uint8_t ip6_un1_nxt;	/* next header */
			uint8_t ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		uint8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits tclass */
	} ip6_ctlun;
	struct in6_addr ip6_src;	/* source address */
	struct in6_addr ip6_dst;	/* destination address */
};

/* Generic extension header.  */
struct ip6_ext {
	uint8_t ip6e_nxt;	/* next header.  */
	uint8_t ip6e_len;	/* length in units of 8 octets.  */
};

#define MAX_NUM_MPLS_LABELS     10
#define MPLS_LABEL_LEN           3
#define ALARM_SLEEP       1
#define DEFAULT_SNAPLEN 1600	//256

struct mpls_labels {
	u_short numMplsLabels;
	u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN];
};

#include "packet.h"

#ifndef DLT_ANY
#define DLT_ANY 113
#endif

/* BSD AF_ values. */
#define BSD_AF_INET             2
#define BSD_AF_INET6_BSD        24	/* OpenBSD (and probably NetBSD), BSD/OS */
#define BSD_AF_INET6_FREEBSD    28
#define BSD_AF_INET6_DARWIN     30

/* ************************************ */

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800	/* IP protocol */
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6          0x86DD	/* IPv6 protocol */
#endif

#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS          0x8847	/* MPLS protocol */
#endif

#ifndef ETHERTYPE_MPLS_MULTI
#define ETHERTYPE_MPLS_MULTI    0x8848	/* MPLS multicast packet */
#endif

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN          0x08100
#endif

typedef struct ipV4Fragment {
	u_int32_t src, dst;
	u_short fragmentId, numPkts, len, sport, dport;
	time_t firstSeen;
	struct ipV4Fragment *next;
} IpV4Fragment;

struct ether_mpls_header {
	u_char label, exp, bos;
	u_char ttl;
};

struct ppp_header {
	u_int8_t address, control;
	u_int16_t proto;
};

typedef struct ether80211q {
	u_int16_t vlanId;
	u_int16_t protoType;
} Ether80211q;

struct ether_vlan_header {
	u_char evl_dhost[ETHER_ADDR_LEN];
	u_char evl_shost[ETHER_ADDR_LEN];
	u_int16_t evl_encap_proto;
	u_int16_t evl_tag;
	u_int16_t evl_proto;
};

typedef struct anyHeader {
	u_int16_t pktType;
	u_int16_t llcAddressType;
	u_int16_t llcAddressLen;
	u_char ethAddress[6];
	u_int16_t pad;
	u_int16_t protoType;
} AnyHeader;

#define NULL_HDRLEN             4

#define MAX_NUM_NETWORKS 16

#define CONST_NETWORK_ENTRY                 0
#define CONST_NETMASK_ENTRY                 1
#define CONST_BROADCAST_ENTRY               2
#define CONST_NETMASK_V6_ENTRY              3
#define CONST_INVALIDNETMASK                -1

#define CONST_NETWORK_SIZE                  4	/* [0]=network, [1]=mask, [2]=broadcast [3]=mask v6 */

#define MAX_RB_SIZE  (4096*16)
typedef struct _record_buf {
	char buf[MAX_RB_SIZE];
	int pos;
} RB;


typedef struct _AThread {
	pthread_t thread;
} AThread;

#define FIELD_SEP	'|'

extern unsigned char smac[];
extern unsigned char dmac[];

extern pcap_t *pd;

extern struct pcap_stat pcapStats;

extern u_int64_t totPkts, totLost;
extern struct timeval startTime;
extern unsigned long long numPkts, numBytes ;

extern 	int32_t gmt2local (time_t t);

extern inline void gotPacket (u_char * _deviceId, const struct pcap_pkthdr *h, const u_char * p);
extern void destroy_processor ();
extern bool init_iprange( );
extern void print_stats ();

#endif

