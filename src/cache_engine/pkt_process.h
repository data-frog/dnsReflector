#ifndef _PKT_PROCESS_H_
#define _PKT_PROCESS_H_

#include "packet.h"
#include "urlmatch.h"

extern void handle_http_packet(pkt_data *pkt);
extern int  handle_dns_packet(const pkt_data *pkt);

extern url_hash_table  * g_url_hash_table , * g_url_hash_table_reload ;
extern new_dns_hash_table  * g_dns_hash_table , * g_dns_hash_table_reload ;
extern url_hash_table  * g_url_extensions_hash_table ,* g_url_extensions_hash_table_reload ;

extern int max_extension_len;

typedef struct _pkt_field{
        char *host;
        char *referer;
        char *cookie;
        char *user_agent;
}pkt_field;

#define lower_it(key)\
	{\
	char *p = key;\
	while(*p!='\0'){\
		*p = tolower(*p);\
		p++;\
	}\
}

extern char* parseField(const char * payload,const char *field);
#define parseHost(payload) parseField(payload,"Host:")
#define parseRange(payload)  parseField(payload,"Range:")

#endif


