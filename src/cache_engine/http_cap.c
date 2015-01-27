/*
 *
 * gcc pcount.c -o pcount -lpcap
 *
 * VLAN support courtesy of Vincent Magnin <vincent.magnin@ci.unil.ch>
 *
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#include <time.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <pthread.h>
#include "global.h"
#include "http_sqs.h"
#include "reflect.h"
#include "loadconf.h"
#include "logger.h"
#include "pkt_process.h"
#include "ref_time.h"
#include "http_cap.h"

#include "cap_pkt.h"

pcap_t *pd;

u_int64_t totPkts, totLost;
struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;

ngx_pool_t   *spool_black =NULL;
ngx_pool_t   *spool_white =NULL;
ngx_radix_tree_t *sipr_tree_black = NULL;
ngx_radix_tree_t *sipr_tree_white = NULL;

void parse_iprange_file(char *fn, ngx_radix_tree_t * tree, bool has_default);
void destroy_pools( );

volatile long total_http_pkt_count = 0;
volatile long total_dns_pkt_count = 0;

	void
print_stats ()
{
	if(NULL==pd) return ;

	struct pcap_stat pcapStat;
	struct timeval endTime;
	float deltaSec;
	static u_int64_t lastPkts = 0;
	u_int64_t diff;
	static struct timeval lastTime;

	gettimeofday (&endTime, NULL);
	deltaSec = (double) delta_time (&endTime, &startTime) / 1000000;

	if (pcap_stats (pd, &pcapStat) >= 0)
		fprintf (stderr, "=========================\n"
				"Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
				"Total Pkts=%d/Dropped=%.1f %%\n",
				pcapStat.ps_recv, pcapStat.ps_drop,
				pcapStat.ps_recv - pcapStat.ps_drop,
				pcapStat.ps_recv ==
				0 ? 0 : (double) (pcapStat.ps_drop * 100) /
				(double) pcapStat.ps_recv);
	fprintf (stderr,
			"%llu pkts [%.1f pkt/sec] - %llu bytes [%.2f Mbit/sec]\n",
			numPkts, (double) numPkts / deltaSec, numBytes,
			(double) 8 * numBytes / (double) (deltaSec * 1000000));

	deltaSec = (double) delta_time (&endTime, &lastTime) / 1000000;
	diff = pcapStat.ps_recv - lastPkts;
	fprintf (stderr, "=========================\n"
			"Actual Stats: %lu pkts [%.1f ms][%.1f pkt/sec]\n",
			diff, deltaSec * 1000, ((double) diff / (double) (deltaSec)));
	lastPkts = pcapStat.ps_recv;

	lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

	fprintf (stderr, "=========================\n");
}

void destroy_processor ()
{
	debug("destroy_processor\n");
	int status,i ;
	if(log_thread_id) pthread_join(log_thread_id,(void *)&status);
	for(i=0;i<sizeof(http_thread_ids)/sizeof(pthread_t);i++)
	{
		//printf("http thread %d quit, tid : %d.\n",i,http_thread_ids[i]);	
		if(0 != http_thread_ids[i])
			pthread_join(http_thread_ids[i],(void *)&status);
	}
	for(i=0;i<sizeof(dns_thread_ids)/sizeof(pthread_t);i++)
	{
		//printf("dns thread %d quit, tid : %d.\n",i,dns_thread_ids[i]);	
		if(0 != dns_thread_ids[i])
			pthread_join(dns_thread_ids[i],(void *)&status);
	}

	/*url_hash_table_destroy(g_dns_hash_table);
	url_hash_table_destroy(g_url_hash_table);
	url_hash_table_destroy(g_url_extensions_hash_table);
	url_hash_table_destroy(g_dns_hash_table_reload);
	url_hash_table_destroy(g_url_hash_table_reload);
	url_hash_table_destroy(g_url_extensions_hash_table_reload);
	*/
	//destroy_pools( );
}

/*
 * A faster replacement for inet_ntoa().
 */
	char *
_intoa (unsigned int addr, char *buf, u_short bufLen)
{
	char *cp, *retStr;
	u_int byte;
	int n;

	cp = &buf[bufLen];
	*--cp = '\0';

	n = 4;
	do
	{
		byte = addr & 0xff;
		*--cp = byte % 10 + '0';
		byte /= 10;
		if (byte > 0)
		{
			*--cp = byte % 10 + '0';
			byte /= 10;
			if (byte > 0)
				*--cp = byte + '0';
		}
		*--cp = '.';
		addr >>= 8;
	}
	while (--n > 0);

	/* Convert the string to lowercase */
	retStr = (char *) (cp + 1);

	return (retStr);
}

/* ************************************ */

	char *
intoa (unsigned int addr)
{
	static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];
	return (_intoa (addr, buf, sizeof (buf)));
}

void handlePacket(const pkt_data *pkt)
{	
	++ total_dns_pkt_count ;
	handle_dns_packet( pkt );	
	return ;
}

inline void gotPacket (u_char * _deviceId, const struct pcap_pkthdr *h, const u_char * pkt)
{
	if(quit)
		return ;
	
	cap_pkt_t	cap_pkt_data;
	cap_pkt_t	*cap_pkt = &cap_pkt_data;
	struct pfring_pkthdr *hdr = cappkt_hdr(cap_pkt);
	uint16_t	offset, payload_len;
	uint8_t		*p;
	int 		ret;

	hdr->extended_hdr.parsed_pkt.offset.eth_offset = 0;
	hdr->extended_hdr.parsed_pkt.offset.vlan_offset = 0;
	hdr->extended_hdr.parsed_pkt.offset.l3_offset = 0;
	hdr->extended_hdr.parsed_pkt.offset.l4_offset = 0;
	hdr->extended_hdr.parsed_pkt.offset.payload_offset = 0;
	hdr->caplen = h->caplen;

	ret = pfring_parse_pkt((u_char *)pkt, hdr, 4, 0, 0);
	if(ret != 4) return;

	if(cappkt_l3_proto(cap_pkt) != IPPROTO_UDP || cappkt_udp_dport(cap_pkt) != 53) return;

	offset = hdr->extended_hdr.parsed_pkt.offset.payload_offset;
	if(h->caplen < offset) return;

	payload_len = h->caplen - offset;
	if(payload_len > RFLGAI_CAPPKT_PAYLOAD_MAXLEN) return;

	if (ngx_radix32tree_find(sipr_tree_white, cappkt_ip_saddr(cap_pkt)) \
			== NGX_RADIX_NO_VALUE || 
			ngx_radix32tree_find(sipr_tree_black, cappkt_ip_saddr(cap_pkt)) \
			!= NGX_RADIX_NO_VALUE){
#if 0
		if (isdebug){
			int ips = src.ipType.ipv4;
			int ip_i = ips;
			snprintf (ip_s, sizeof (ip_s), "%d.%d.%d.%d",
					(ip_i >> 24) & 0xff, (ip_i >> 16) & 0xff,
					(ip_i >> 8) & 0xff, (ip_i) & 0xff);
			int ipd = dst.ipType.ipv4;
			ip_i = ipd;
			snprintf (ip_d, sizeof (ip_d), "%d.%d.%d.%d",
					(ip_i >> 24) & 0xff, (ip_i >> 16) & 0xff,
					(ip_i >> 8) & 0xff, (ip_i) & 0xff);
			debug("Skipped %s:%d=>%s:%d\n",ip_s,sport, ip_d, dport);
		}
#endif
		return ;
	}

	p = (uint8_t *)pkt + offset;
	p[payload_len - 1] = '\0';
	cap_pkt->payload = p;
	cap_pkt->payload_len = payload_len;

	handlePacket(cap_pkt);
}

void parse_iprange_file(char *fn, ngx_radix_tree_t * tree, bool has_default)
{
	char *line= NULL,*mask =NULL;
	int idx =0;
	char tmp[4096];
	fprintf(stderr,"Load iprange from file %s\n",fn);
	FILE *fp = fopen(fn,"r");
	if (fp == NULL){
		fprintf(stderr,"Can not open iprange file:%s\n",fn);
		goto END;
	}

	while(!feof(fp)){
		line= fgets(tmp,sizeof(tmp),fp);
		if (line == NULL||line[0]=='#')
			continue;
		mask = strchr(line,'/');
		if (mask != NULL){
			*mask = '\0';
			mask++;
		}
		struct in_addr in ;
		if(inet_aton(line,&in) == 0)
			continue;

		uint32_t net= htonl(in.s_addr);
		uint32_t mask1 = 0xFFFFFFFF;
		int maskbit = 32;

		if (mask != NULL)
			maskbit = atoi(mask);

		if (maskbit>0 && maskbit<=32)
			mask1 = ~((1<<(32-maskbit)) -1);
		else if (maskbit == 0)
			mask1 = 0x0;

		if (ngx_radix32tree_insert(tree, net , mask1, 1 )== NGX_OK){
			debug("add iprange:net=%x,mask=%x\n",net,mask1);
			idx ++;
		}
	}
	fclose(fp);

END:
	if(has_default && idx == 0)
	{
		ngx_radix32tree_insert(tree, 0, 0x0, 1 ); //  0.0.0.0/0
	}
	return  ;
}
 
bool init_iprange( )
{
 	ngx_pagesize = getpagesize();
 	spool_black = ngx_create_pool(16384, NULL);
 	spool_white = ngx_create_pool(16384, NULL);
 	if (spool_black == NULL || spool_white == NULL) {
 		fprintf(stderr,"Can not create pool\n");
 		return false;
 	}
 
 	sipr_tree_black  = ngx_radix_tree_create(spool_black, -1);
 	sipr_tree_white  = ngx_radix_tree_create(spool_white, -1);
 	if (sipr_tree_black == NULL || sipr_tree_white == NULL) {
 		fprintf(stderr,"Can not create tree\n");
 		return false;
 	}

 	parse_iprange_file(BLACK_SRC_LIST_NAME,sipr_tree_black,false);
 	parse_iprange_file(WHITE_SRC_LIST_NAME,sipr_tree_white,true);

	return true ;	
}

void destroy_pools( )
{
	if(NULL!=spool_black)ngx_destroy_pool(spool_black);
	if(NULL!=spool_white)ngx_destroy_pool(spool_white);
}

