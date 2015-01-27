#include <errno.h>
#include <arpa/inet.h>
#include <assert.h>
#include "global.h"
#include "packet.h"
#include "libdns/dns.h"
#include "pkt_process.h"
#include "hostlist.h"

int max_extension_len = 0 ;

url_hash_table  * g_url_hash_table , * g_url_hash_table_reload ;
new_dns_hash_table  * g_dns_hash_table , * g_dns_hash_table_reload ;
url_hash_table  * g_url_extensions_hash_table ,* g_url_extensions_hash_table_reload ;

static char *parse_value(char *field){
	// formation : [KEY : VALUE \r\n]
	assert (field != NULL);
	char *p = strchr(field,'\012');
	if( p != NULL)
		*p = '\0';
	p = strchr(field,'\015');
	if( p != NULL)
		*p = '\0';
	p = strchr(field,':');
	if(p != NULL){
		++p;
		while(p!= NULL && *p ==' ') p++;
	}

	return p;
}

char* parseField(const char * payload,const char *field)
{
	char * value = NULL;
	assert(payload != NULL);

	char *t = strstr(payload,field);
	if(NULL==t) return NULL;
	value = parse_value(t);	
	return value;
}

void handle_http_packet(pkt_data *pkt)
{
#if 0
	u_char *payload = (u_char *)pkt->p; 
	u_char *p = &payload[strlen(GET_URL) - 1];
	char c;
	char *q = NULL, *r;
	char *host = NULL ;
	char *range = NULL ;
	domain_addr_pair *dest_url_pair;

	if(0 == g_url_hash_table->num) return;
	if(0 != strncmp(GET_URL,payload,strlen(GET_URL))) return ;	
	
	char *url = p;
	// skip the " \t\012\015" at the initial portion 
	url += strspn(url, " \t\012\015");
	// p is a pointer the first occurrence in " \t\012\015"
	p = strpbrk(url, " \t\012\015");

	if( NULL== p ) // Single line 
		return ; 
	
	// parse Host
	host = parseHost(p);
	if(host == NULL)
		return ;
	*p = '\0';
	
	char *end = strchr(url,'?');
	if(end) *end = 0;

	// Skip reflected request 
	// debug("host :[%s], squid_ip :[%s]\n",host,squid_ip);
	if(0==strcmp(host,squid_ip))
		return ;
	
	// Match the extension name 
	char *extension = strrchr(url,'.');
	if(NULL == extension || max_extension_len < strlen(extension+1))
		goto exit;
	else
	{
		// debug("extension: %s\n",extension);
		dest_url_pair = url_hash_table_find(g_url_extensions_hash_table,extension+1);
		if(NULL==dest_url_pair)
			goto exit;
	}

	char myurl[MAX_PAYLOAD_LEN + 100];
	int pos = snprintf(myurl,sizeof(myurl),"http://%s%s",host,url);	
	myurl[pos]='\0';
	
	dest_url_pair = url_hash_table_find(g_url_hash_table,myurl);
	if(NULL==dest_url_pair)
		goto exit;
	else 
	{
		char buf[MAX_PAYLOAD_LEN +512] = {0};
		char nr[MAX_PAYLOAD_LEN] = {0};
		snprintf(nr, sizeof(nr), "%s", dest_url_pair->reflect_addr);
		snprintf(buf, sizeof(buf), "%.20s %d %s\015\012Location: %s\015\012\015\012","HTTP/1.1",302,"Found",nr);
//		send_faked_tcp_packet(pkt,buf,strlen(buf));

		my_send_faked_tcp_packet(pkt,buf,strlen(buf));

		debug("hit http big file:%s\n",url);
	}
exit:
	return ;
#endif
}

int handle_dns_packet(const pkt_data *pkt)
{
	const unsigned char *payload = cappkt_payload(pkt);
	dns_response_pair  *dest_dns_pair = NULL ;
	char qname[DNS_D_MAXNAME + 1];
	size_t qlen;
	struct dns_packet *P	= dns_p_new(512);
	struct dns_rr rr;
	int error;
	size_t ii, jj ,len, qname_len;
	
	//Limit the max length
	len = P->size - 1;
	if( len > cappkt_payload_len(pkt))
		len = cappkt_payload_len(pkt);
	else
		goto err_done;

	if(len <= 5)
		goto err_done;

	// memcpy(P->data, payload, len);
	for( ii = 0 ; ii < len ; ii++)
		*(P->data +ii) = *(payload + ii);
	P->end  = len;
	
	memset(qname,0,sizeof(qname));
	//only dns query
	if(dns_header(P)->qr != 0 
	   ||( dns_header(P)->opcode !=DNS_OP_QUERY ))
		goto err_done;

	if ((error = dns_rr_parse(&rr, 12, P)))
		goto err_done;

	//if(rr.type !=DNS_T_A)
	if(rr.type !=DNS_T_A && rr.type != DNS_T_AAAA)
		goto err_done;
	if (0 == (qlen = dns_d_expand(qname,DNS_D_MAXNAME, rr.dn.p, P, &error)))
		goto err_done;

	if (qlen >= sizeof(qname)-1)
		{ error = EINVAL; goto err_done; }
	
	qname_len = strlen(qname);
	qname[qname_len - 1] = 0 ;
	// size_t qn_len = strlen(qname);
	// qname[qn_len-1] = 0 ;

	if(isdebug){
		printf("qname:%s len:%ld\n", qname, qname_len - 1);
	}

	if(!hostlist_pass((unsigned char*)qname, qname_len - 1)){
		if(isdebug){
			printf("BLACK_HOST %s\n", qname);
		}
		goto err_done;
	}

	dest_dns_pair = dns_hash_table_find(g_dns_hash_table,qname);
	if(NULL==dest_dns_pair)
	{
		goto err_done;
	}

	strcat(qname,".");
	// qname[qn_len] = '.' ;
	// qname[qn_len+1] = 0 ;
	struct dns_packet *Q	= dns_p_new(1024);

	if ((error = dns_p_push(Q, DNS_S_QD, qname, qlen, DNS_T_A, DNS_C_IN, 0, NULL)))
	{
		fprintf(stderr,"Can not add query section\n");
		goto err_done ;
	}

	if (isdebug){
		printf("hit : %s, %d \n", qname, dest_dns_pair->server_cnt );
	}
	
	for( jj = 0 ; jj < dest_dns_pair->server_cnt ; jj ++ )
	{
		addr_list * found = dest_dns_pair->now ;	
		int iserv_ip = found->data ;
		dest_dns_pair->now = dest_dns_pair->now->next ;
	
		if ((error = dns_p_push(Q, DNS_S_AN, qname, qlen, DNS_T_A, DNS_C_IN, 600, &iserv_ip)))
		{
			fprintf(stderr,"Can not add query section\n");
			goto err_done ;
		}
		dns_header(Q)->qr	= 1;
		dns_header(Q)->rd	= dns_header(P)->rd;
		dns_header(Q)->ra	= dns_header(P)->rd;
		dns_header(Q)->qid	= dns_header(P)->qid;
	}
		
	my_send_faked_udp_packet(pkt,Q->data,Q->end);	
	dest_dns_pair->now = dest_dns_pair->now->next ;
	if (isdebug){
		printf("Send for %s\n",qname);
	}
err_done:
	return 1;
}

