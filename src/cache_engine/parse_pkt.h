#ifndef _PARSE_PKT_H_
#define _PARSE_PKT_H_

//#include "bittypes.h"
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#if 0
#define __LITTLE_ENDIAN_BITFIELD /* FIX */

#ifndef __NETINET_IP_H /*we do not include <netinet/ip.h>*/

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
  u_int8_t	ihl:4,
    version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
  u_int8_t	version:4,
    ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
  u_int8_t	tos;
  u_int16_t	tot_len;
  u_int16_t	id;
  u_int16_t	frag_off;
  u_int8_t	ttl;
  u_int8_t	protocol;
  u_int16_t	check;
  u_int32_t	saddr;
  u_int32_t	daddr;
  /*The options start here. */
};
#endif

#ifndef _NETINET_TCP_H /*we do not include <netinet/tcp.h>*/
struct tcphdr {
  u_int16_t	source;
  u_int16_t	dest;
  u_int32_t	seq;
  u_int32_t	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
  u_int16_t res1:4,
    doff:4,
    fin:1,
    syn:1,
    rst:1,
    psh:1,
    ack:1,
    urg:1,
    ece:1,
    cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
  u_int16_t	doff:4,
    res1:4,
    cwr:1,
    ece:1,
    urg:1,
    ack:1,
    psh:1,
    rst:1,
    syn:1,
    fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
  u_int16_t	window;
  u_int16_t	check;
  u_int16_t	urg_ptr;
};
#endif

#ifndef __NETINET_UDP_H /*we do not include <netinet/udp.h>*/
struct udphdr {
  u_int16_t	source;
  u_int16_t	dest;
  u_int16_t	len;
  u_int16_t	check;
};
#endif

struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
  u_int8_t		priority:4,
		version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
  u_int8_t		version:4,
		priority:4;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
  u_int8_t		flow_lbl[3];

  int16_t	    payload_len;
  u_int8_t		nexthdr;
  u_int8_t		hop_limit;

  struct _in6_addr saddr;
  struct _in6_addr daddr;
};

struct ipv6_opt_hdr {
  u_int8_t		nexthdr;
  u_int8_t 		hdrlen;
	/* TLV encoded option data follows */
} __attribute__((packed));

#define ipv4_tos     ip_tos
#define ipv6_tos     ip_tos
#define ipv4_src     ip_src.v4
#define ipv4_dst     ip_dst.v4
#define ipv6_src     ip_src.v6
#define ipv6_dst     ip_dst.v6
#define host4_low    host_low.v4
#define host4_high   host_high.v4
#define host6_low    host_low.v6
#define host6_high   host_high.v6
#define host4_peer_a host_peer_a.v4
#define host4_peer_b host_peer_b.v4
#define host6_peer_a host_peer_a.v6
#define host6_peer_b host_peer_b.v6

#endif 

#define ETH_ALEN       6   /* Ether address length */

struct eth_hdr {
  unsigned char   h_dest[ETH_ALEN];       /* destination eth addr */
  unsigned char   h_source[ETH_ALEN];     /* source ether addr    */
  u_int16_t       h_proto;                /* packet type ID field */
};

/*
 * ppp packet for protocol field len is 2 bytes
 */
struct ppp2hdr{
	u_int16_t	protocol;
};

#if 1
/* IPv6 address */
struct _in6_addr
{
    union
    {
        u_int8_t        u6_addr8[16];
        u_int16_t       u6_addr16[8];
        u_int32_t       u6_addr32[4];
    } in6_u;
#define s6_addr                 in6_u.u6_addr8
#define s6_addr16               in6_u.u6_addr16
#define s6_addr32               in6_u.u6_addr32
#define s6_addr64               in6_u.u6_addr64
};
#endif

typedef union {
    struct _in6_addr v6;  /* IPv6 src/dst IP addresses (Network byte order) */
    u_int32_t v4;        /* IPv4 src/dst IP addresses */
} ip_addr;

#define TH_FIN_MULTIPLIER	0x01
#define TH_SYN_MULTIPLIER	0x02
#define TH_RST_MULTIPLIER	0x04
#define TH_PUSH_MULTIPLIER	0x08
#define TH_ACK_MULTIPLIER	0x10
#define TH_URG_MULTIPLIER	0x20

#define NEXTHDR_HOP     	  0
#define NEXTHDR_TCP     	  6
#define NEXTHDR_UDP     	 17
#define NEXTHDR_IPV6    	 41
#define NEXTHDR_ROUTING 	 43
#define NEXTHDR_FRAGMENT	 44
#define NEXTHDR_ESP     	 50
#define NEXTHDR_AUTH    	 51
#define NEXTHDR_ICMP    	 58
#define NEXTHDR_NONE    	 59
#define NEXTHDR_DEST    	 60
#define NEXTHDR_MOBILITY	135

/*
 *   Note that as offsets *can* be negative,
 *     please do not change them to unsigned
 *     */
struct pkt_offset {
  int16_t eth_offset; /* This offset *must* be added to all offsets below */
  int16_t vlan_offset;
  int16_t l3_offset;
  int16_t l4_offset;
  int16_t payload_offset;
};

struct pkt_flow_info {
  u_int32_t in_iface, out_iface, samplingPopulation, flow_sequence;
};

struct pkt_aggregation_info {
  u_int32_t num_pkts, num_bytes;
  struct timeval first_seen, last_seen;
};

typedef union {
  struct pkt_flow_info flow; /* Flow Information */
  struct pkt_aggregation_info aggregation; /* Future or plugin use */
} packet_user_detail;

struct pkt_parsing_info {
    /* Core fields (also used by NetFlow) */
    u_int8_t dmac[ETH_ALEN], smac[ETH_ALEN];  /* MAC src/dst addresses */
    u_int16_t eth_type;   /* Ethernet type */
    u_int16_t vlan_id;    /* VLAN Id or NO_VLAN */
    u_int8_t  ip_version;
    u_int8_t  l3_proto, ip_tos; /* Layer 3 protocol/TOS */
    ip_addr   ip_src, ip_dst;   /* IPv4 src/dst IP addresses */
    u_int16_t l4_src_port, l4_dst_port; /* Layer 4 src/dst ports */
    struct {
        u_int8_t flags;   /* TCP flags (0 if not available) */
        u_int32_t seq_num, ack_num; /* TCP sequence number */
    } tcp;
    u_int16_t last_matched_plugin_id; /* If > 0 identifies a plugin to that matched the packet */
    u_int16_t last_matched_rule_id; /* If > 0 identifies a rule that matched the packet */
    struct pkt_offset offset; /* Offsets of L3/L4/payload elements */

    /* Leave it at the end of the structure */
    packet_user_detail pkt_detail;
};

struct pfring_extended_pkthdr {
  u_int64_t timestamp_ns; /* Packet timestamp at ns precision. Note that if your NIC supports
                                                          hardware timestamp, this is the place to read timestamp from */
  u_int8_t rx_direction;  /* 1=RX: packet received by the NIC, 0=TX: packet transmitted by the NIC */
  int if_index;           /* index of the interface on which the packet has been received.
                                                          It can be also used to report other information */
  u_int32_t pkt_hash;     /* Hash based on the packet header */
  u_int16_t parsed_header_len; /* Extra parsing data before packet */

  /* NOTE: leave it as last field of the memset on parse_pkt() will fail */
  struct pkt_parsing_info parsed_pkt; /* packet parsing info */
};

/* NOTE
 *
 *Keep 'struct pfring_pkthdr' in sync with 'struct pcap_pkthdr'
 **/
struct pfring_pkthdr {
  /* pcap header */
  struct timeval ts;    /* time stamp */
  u_int32_t caplen;     /* length of portion present */
  u_int32_t len;        /* length this packet (off wire) */
  struct pfring_extended_pkthdr extended_hdr; /* PF_RING extended header */
};

int pfring_parse_pkt(u_char *pkt,
        struct pfring_pkthdr *hdr,
        u_int8_t level /* 2..4 */,
        u_int8_t add_timestamp /* 0,1 */,
        u_int8_t add_hash /* 0,1 */);

#endif
