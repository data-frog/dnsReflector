#ifndef XFG_RFLGAI_CAPPKT_H
#define XFG_RFLGAI_CAPPKT_H

#include <stdint.h>

#include "parse_pkt.h"

#define RFLGAI_CAPPKT_PAYLOAD_MAXLEN	1600
#define RFLGAI_CAPPKT_HOST_MAXLEN		256
#define MAX_PAYLOAD_LEN		RFLGAI_CAPPKT_PAYLOAD_MAXLEN

struct cap_pkt_s{
	struct pfring_pkthdr	hdr;

	uint16_t	payload_len;
	uint8_t		*payload;
	uint8_t		gap[RFLGAI_CAPPKT_HOST_MAXLEN];
	uint8_t		p[RFLGAI_CAPPKT_PAYLOAD_MAXLEN];
};
typedef struct cap_pkt_s cap_pkt_t;


#define cappkt_tcp_sport(pkt) ((pkt)->hdr.extended_hdr.parsed_pkt.l4_src_port)
#define cappkt_tcp_dport(pkt) ((pkt->hdr.extended_hdr.parsed_pkt.l4_dst_port))
#define cappkt_tcp_acknum(pkt) ((pkt->hdr.extended_hdr.parsed_pkt.tcp.ack_num))
#define cappkt_tcp_seqnum(pkt) ((pkt->hdr.extended_hdr.parsed_pkt.tcp.seq_num))

/*
 * for dns reflector
 */
#define cappkt_udp_sport(pkt) ((pkt)->hdr.extended_hdr.parsed_pkt.l4_src_port)
#define cappkt_udp_dport(pkt) ((pkt)->hdr.extended_hdr.parsed_pkt.l4_dst_port)
#define cappkt_l3_proto(pkt) ((pkt)->hdr.extended_hdr.parsed_pkt.l3_proto)

#define cappkt_ip_saddr(pkt) ((pkt->hdr.extended_hdr.parsed_pkt.ip_src.v4))
#define cappkt_ip_daddr(pkt) ((pkt->hdr.extended_hdr.parsed_pkt.ip_dst.v4))

#define cappkt_payload_len(pkt) (pkt)->payload_len
#define cappkt_hdr(pkt)	&((pkt)->hdr)
#define cappkt_payload(pkt)	(pkt)->payload
#endif
