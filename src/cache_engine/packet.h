#ifndef _PACKET_H_
#define _PACKET_H_

#if 0
#ifndef _WITH_LINUX_KERNEL_HDR
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#else
#ifdef _REENTRANT
#   undef _REENTRANT
#   define _WAS_REENTRANT
#endif
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/if_arp.h>
#include <linux/if.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#ifdef _WAS_REENTRANT
#define _REENTRANT
#   undef _WAS_REENTRANT
#endif
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>

//#define VERSION "1.5"

//#define max(a, b)   ((a) > (b) ? (a) : (b))
//#define min(a, b)   ((a) > (b) ? (b) : (a))

#define IP_DF           0x4000          /* Flag: "Don't Fragment"       */
#define BUFSIZE     512
#define IPHDR       20
#define TCPHDR      20

#include "net.h"
#include "udp_spec.h"
#include "tcp_spec.h"

#define MAX_PAYLOAD_LEN	1024
// #define MAX_URL_LEN 512


typedef struct _pkt_data {
	struct _pkt_data *next;
	//struct _pkt_data *prev;
	//struct pcap_pkthdr *h;
	time_t tv_sec;		// cap time
	int	tv_usec;
	int proto;
	//u_char *p;
	int payloadLen;
	int dataLen;
	IpAddress src;
	u_short sport;
	IpAddress dst;
	u_short dport;
	u_short ip_id;
	struct tcphdr_d tp;
	struct udphdr_d up;
	struct ip ip_hdr;

    struct ether_header ehdr;	
	char p[MAX_PAYLOAD_LEN+1];
	int tocheck;
} pkt_data;

/**
 * Initialize the raw socket here
 * @Note: IMPORTANT - this should be called before calling the following functions
 */
void init_link_socket();

/**
 * Send tcp packet
 *
 */
int send_tcp_packet(struct tcp_spec *ts);

/**
 * Send udp packet
 *
 */
int send_udp_packet(struct udp_spec *ts);

/**
 * Send faked tcp packet
 *
 * @param	pkt	the information of the received packet
 * @param	data	data to send
 * @param	data_len	the length of data
 *
 */
void send_faked_tcp_packet(pkt_data *pkt,char *data, int data_len);

/**
 * Send faked udp packet
 *
 * @param	pkt	the information of the received packet
 * @param	data	data to send
 * @param	data_len	the length of data
 *
 */
void send_faked_udp_packet(pkt_data *pkt,char *data, int data_len);

#endif
#include "cap_pkt.h"

typedef cap_pkt_t pkt_data;

extern void my_send_faked_tcp_packet(pkt_data* pkt,unsigned char* data,int data_len);
extern inline int  my_send_faked_udp_packet(const pkt_data* pkt,unsigned char* data,int data_len);

#endif /*_PACKET_H_*/
