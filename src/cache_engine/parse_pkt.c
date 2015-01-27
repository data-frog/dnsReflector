#include <stdio.h>

#include <arpa/inet.h>
#include <sys/time.h>

//#include "bittypes.h"
#include "parse_pkt.h"


static u_int32_t pfring_hash_pkt(struct pfring_pkthdr *hdr) {
  return
    hdr->extended_hdr.parsed_pkt.vlan_id +
    hdr->extended_hdr.parsed_pkt.l3_proto +
    hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[0]+
    hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[1] +
    hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[2] +
    hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[3] +
    hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[0] +
    hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[1] +
    hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[2] +
    hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[3] +
    hdr->extended_hdr.parsed_pkt.l4_src_port +
    hdr->extended_hdr.parsed_pkt.l4_dst_port;
}

/*
 * 参考test_platform解包代码。对IPV6报文，IPV4分段报文不进行解析处理
 *
 * 添加了PPPoE报文解析, PPPoE的解析在L2层完成
 */
int pfring_parse_pkt(u_char *pkt,
        struct pfring_pkthdr *hdr,
        u_int8_t level /* 2..4 */,
        u_int8_t add_timestamp /* 0,1 */,
        u_int8_t add_hash /* 0,1 */)
{

    struct eth_hdr *eh = (struct eth_hdr*) pkt;
    u_int32_t displ, ip_len, pppoe_len;
    u_int analized = 0;

    /* Note: in order to optimize the computation, this function expects a zero-ed
     * or partially parsed pkthdr */
    //memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
    //hdr->extended_hdr.parsed_header_len = 0;

    if (hdr->extended_hdr.parsed_pkt.offset.l3_offset != 0) {
        goto L3;
    }

    hdr->extended_hdr.parsed_pkt.eth_type = ntohs(eh->h_proto);
    hdr->extended_hdr.parsed_pkt.offset.eth_offset = 0;

    if (hdr->extended_hdr.parsed_pkt.eth_type == 0x8100 /* 802.1q (VLAN) */) {
        hdr->extended_hdr.parsed_pkt.offset.vlan_offset = hdr->extended_hdr.parsed_pkt.offset.eth_offset + sizeof(struct eth_hdr);
        hdr->extended_hdr.parsed_pkt.vlan_id = (pkt[hdr->extended_hdr.parsed_pkt.offset.eth_offset + 14] & 15) * 256 + pkt[hdr->extended_hdr.parsed_pkt.offset.eth_offset + 15];
        hdr->extended_hdr.parsed_pkt.eth_type = (pkt[hdr->extended_hdr.parsed_pkt.offset.eth_offset + 16]) * 256 + pkt[hdr->extended_hdr.parsed_pkt.offset.eth_offset + 17];
        displ = 4;
    } else {
        hdr->extended_hdr.parsed_pkt.vlan_id = 0; /* Any VLAN */
        displ = 0;
    }

	if(hdr->extended_hdr.parsed_pkt.eth_type == 0X8864){/*PPPoE Session*/
		/*
		 * by now we just process ppp packet which protocol field is 2 bytes
		 */
		struct ppp2hdr *h = (struct ppp2hdr *)(&pkt[sizeof(struct eth_hdr) + displ + 6 /* Just Skip PPPoE Session Packet */]);
		/*
		 * if(h->protocol == ntohs(0x0021)){
		 */
		if(h->protocol == 0X2100){
			hdr->extended_hdr.parsed_pkt.eth_type = 0x0800;
		}

		pppoe_len = 8;
	}else{
		pppoe_len = 0;
	}

    hdr->extended_hdr.parsed_pkt.offset.l3_offset = hdr->extended_hdr.parsed_pkt.offset.eth_offset + displ + pppoe_len + sizeof(struct eth_hdr);

L3:

    analized = 2;

    if (level < 3) {
        goto TIMESTAMP;
    }

    if (hdr->extended_hdr.parsed_pkt.offset.l4_offset != 0) {
        goto L4;
    }

    if (hdr->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4 */) {
        struct iphdr *ip;

        hdr->extended_hdr.parsed_pkt.ip_version = 4;

        if (hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l3_offset + sizeof(struct iphdr)) {
            goto TIMESTAMP;
        }

        ip = (struct iphdr *)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l3_offset]);

        hdr->extended_hdr.parsed_pkt.ip_src.v4 = ntohl(ip->saddr);
        hdr->extended_hdr.parsed_pkt.ip_dst.v4 = ntohl(ip->daddr);
        hdr->extended_hdr.parsed_pkt.l3_proto = ip->protocol;
        hdr->extended_hdr.parsed_pkt.ip_tos = ip->tos;
		if(ntohs(ip->frag_off) & 0x3fff){
			goto TIMESTAMP;//fragment packet
		}
        ip_len = ip->ihl * 4;
    }
#if 0
   	else if(hdr->extended_hdr.parsed_pkt.eth_type == 0x86DD /* IPv6 */) {
		goto TIMESTAMP;
        struct ipv6hdr *ipv6;

        hdr->extended_hdr.parsed_pkt.ip_version = 6;

        if (hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l3_offset + sizeof(struct ipv6hdr)) {
            goto TIMESTAMP;
        }

        ipv6 = (struct ipv6hdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l3_offset]);

        /* Values of IPv6 addresses are stored as network byte order */
        hdr->extended_hdr.parsed_pkt.ipv6_src = ipv6->saddr;
        hdr->extended_hdr.parsed_pkt.ipv6_dst = ipv6->daddr;
        hdr->extended_hdr.parsed_pkt.l3_proto = ipv6->nexthdr;
        hdr->extended_hdr.parsed_pkt.ipv6_tos = ipv6->priority; /* IPv6 class of service */
        ip_len = 40;

        while (hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_HOP	   ||
                hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_DEST	   ||
                hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ROUTING ||
                hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_AUTH	   ||
                hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ESP	   ||
                hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_FRAGMENT) {

            struct ipv6_opt_hdr *ipv6_opt;
            ipv6_opt = (struct ipv6_opt_hdr *)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len]);
            ip_len += 8;
            if (hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_AUTH) {
                /*
                   RFC4302 2.2. Payload Length: This 8-bit field specifies the
                   length of AH in 32-bit words (4-byte units), minus "2".
                   */
                ip_len += ipv6_opt->hdrlen * 4;
            } else if (hdr->extended_hdr.parsed_pkt.l3_proto != NEXTHDR_FRAGMENT) {
                ip_len += ipv6_opt->hdrlen;
            }

            hdr->extended_hdr.parsed_pkt.l3_proto = ipv6_opt->nexthdr;
        }
    } 
#endif
	else {
        hdr->extended_hdr.parsed_pkt.l3_proto = 0;
        goto TIMESTAMP;
    }

    hdr->extended_hdr.parsed_pkt.offset.l4_offset = hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len;

L4:

    analized = 3;

    if (level < 4)
        goto TIMESTAMP;

    if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP) {
        struct tcphdr *tcp;

        if(hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct tcphdr)) {
            goto TIMESTAMP;
        }

        tcp = (struct tcphdr *)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

        hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(tcp->source), hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(tcp->dest);
        hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + (tcp->doff * 4);
        hdr->extended_hdr.parsed_pkt.tcp.seq_num = ntohl(tcp->seq), hdr->extended_hdr.parsed_pkt.tcp.ack_num = ntohl(tcp->ack_seq);
        hdr->extended_hdr.parsed_pkt.tcp.flags = (tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER) +
            (tcp->rst * TH_RST_MULTIPLIER) + (tcp->psh * TH_PUSH_MULTIPLIER) +
            (tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);

    } else if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_UDP) {
        struct udphdr *udp;

        if(hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr)) {
            goto TIMESTAMP;
        }

        udp = (struct udphdr *)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

        hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(udp->source), hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(udp->dest);
        hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr);

    } else {
        hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
        hdr->extended_hdr.parsed_pkt.l4_src_port = hdr->extended_hdr.parsed_pkt.l4_dst_port = 0;
    }

    analized = 4;

TIMESTAMP:

    if(add_timestamp && hdr->ts.tv_sec == 0) {
        gettimeofday(&hdr->ts, NULL);
    }

    if (add_hash && hdr->extended_hdr.pkt_hash == 0) {
        hdr->extended_hdr.pkt_hash = pfring_hash_pkt(hdr);
    }

    return analized;
}

