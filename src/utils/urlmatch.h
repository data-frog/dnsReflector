#ifndef __REFLACETOR_URLMATCH_H__
#define __REFLACETOR_URLMATCH_H__
#include "global.h"

#define DOMAIN_MAX_LEN 55

#ifndef uchar
#define uchar unsigned char
#endif

#pragma pack(1)

extern int ns_count ;

// define cycle list
typedef struct _addr_list
{
        int data ;
        struct _addr_list * next ;
} addr_list ;

typedef struct _ns_node
{
        char name[DOMAIN_MAX_LEN] ;
        struct _ns_node * next ;
        struct _addr_list  *now ;
        uchar  server_cnt ;
        struct _addr_list  *addrs_head ;
} ns_node ;


#define dns_response_pair ns_node
#define dns_hash_node dns_response_pair

typedef struct _dns_hash_table
{
        dns_hash_node **head ;
        int num ;
}new_dns_hash_table;

typedef struct _domain_addr_pair
{
	char url[MAX_PAYLOAD_LEN];
	char reflect_addr[MAX_PAYLOAD_LEN];
	struct _domain_addr_pair * next ;
}domain_addr_pair;

typedef struct _url_hash_node 
{
	bool used ;
	domain_addr_pair *data ;	
}url_hash_node;

typedef struct _url_hash_table
{
	url_hash_node *head ;
	int num ;
}url_hash_table;

extern void url_hash_table_init(url_hash_table* p_url_hash_table);
extern bool url_hash_table_isfree(const url_hash_table* p_url_hash_table);
extern bool url_hash_table_create(const domain_addr_pair* domain_addr_pair_list,
				  const int num,
				  url_hash_table* p_url_hash_table);
extern domain_addr_pair * url_hash_table_find(const url_hash_table* purl_hash_table,const char* purl);
extern void url_hash_table_destroy(url_hash_table* purl_hash_table);
extern void dump_hash_table( const url_hash_table* purl_hash_table,const char * table_name);

extern void dns_hash_table_init(new_dns_hash_table* p_dns_hash_table);
extern bool dns_hash_table_create(dns_response_pair* dns_response_pair_list,const int list_count ,new_dns_hash_table* p_dns_hash_table);
extern void collision_info(const url_hash_table* p_url_hash_table );

extern dns_response_pair * dns_hash_table_find(const new_dns_hash_table* pdns_hash_table,const char* pdns );
#endif
 
