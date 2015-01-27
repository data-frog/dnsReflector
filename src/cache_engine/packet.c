#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <libnet.h>
#include "packet.h"
#include "global.h"

//libnet_t* net_t=NULL;
extern uint8_t g_hwdst[];

#if 0
void my_send_faked_tcp_packet(pkt_data* pkt,unsigned char* data,int data_len)
{
	libnet_ptag_t p_tag;

	static __be16 count2=1;
	if((count2++)%0xffff==0)
		count2=1;

	p_tag=libnet_build_tcp(ntohs(pkt->tp.th_dport),ntohs(pkt->tp.th_sport),ntohl(pkt->tp.th_ack),ntohl(pkt->tp.th_seq)+pkt->payloadLen,TH_ACK|TH_PUSH|TH_FIN,2048,0,0,20+data_len,data,data_len,net_t,0);
	if(-1==p_tag)
	{
		fprintf(stderr,"libnet_build_tcp failed:%s.\n",libnet_geterror(net_t));
		goto exit;
	}

	p_tag=libnet_build_ipv4(40+data_len,0,count2,0x4000,128,IPPROTO_TCP,0,pkt->ip_hdr.ip_dst.s_addr,pkt->ip_hdr.ip_src.s_addr,0,0,net_t,0);
	if(-1==p_tag)
	{
		fprintf(stderr,"libnet_build_ipv4 failed:%s.\n",libnet_geterror(net_t));
		goto exit;
	}	

	int res;
	if(-1==(res=libnet_write(net_t)))
	{
		fprintf(stderr,"libnet_write failed:%s.\n",libnet_geterror(net_t));
		goto exit;
	}

exit:
	libnet_clear_packet(net_t);
}
#endif

inline int my_send_faked_udp_packet(const pkt_data* pkt,unsigned char* data,int data_len)
{
	int ret = 1 ;
	libnet_ptag_t p_tag;
	static __be16 send_count=1;
	if((send_count++) == 0xffff)
		send_count=1;


	p_tag=libnet_build_udp(cappkt_udp_dport(pkt), cappkt_udp_sport(pkt), \
			LIBNET_UDP_H+data_len, 0, data, data_len, net_t, 0);
	if(-1==p_tag)
	{
		fprintf(stderr,"libnet_build_udp failed:%s.\n",libnet_geterror(net_t));
		ret = 0 ;
		goto exit;
	}

	p_tag=libnet_build_ipv4(20+LIBNET_UDP_H+data_len, 0, send_count, 0x4000, 128, IPPROTO_UDP,\
			0, htonl(cappkt_ip_daddr(pkt)), htonl(cappkt_ip_saddr(pkt)), 0, 0, net_t, 0);
	if(-1==p_tag)
	{
		fprintf(stderr,"libnet_build_ipv4 failed:%s.\n",libnet_geterror(net_t));
		ret = 0 ;
		goto exit;
	}

    p_tag=libnet_autobuild_ethernet(g_hwdst, ETHERTYPE_IP, net_t);
    if(-1==p_tag) {
        fprintf(stderr, "libnet_autobuild_ethernet failed:%s.",libnet_geterror(net_t));
		ret = 0 ;
		goto exit;
    }

	if(-1==libnet_write(net_t))
	{
		fprintf(stderr,"libnet_write failed:%s.\n",libnet_geterror(net_t));
		ret = 0 ;
		goto exit;
	}

exit:
	libnet_clear_packet(net_t);
	return ret ;
}

