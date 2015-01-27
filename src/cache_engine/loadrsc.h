#ifndef _REFLECT_LOADRSC_H_
#define _REFLECT_LOADRSC_H_
#include "urlmatch.h"

extern bool load_url_pair(const char *filename,domain_addr_pair **pdomain_addr_pair_list,const domain_addr_pair *black_list,int* pnum );
extern bool load_url_blacklist(const char *filename,domain_addr_pair **pdomain_addr_pair_list,int* pnum);
#define load_dns_blacklist  load_url_blacklist

extern int get_max_extension_len(const domain_addr_pair *addr_pair_list);

extern void destroy_url_pair(domain_addr_pair *pdomain_addr_pair_list);

#define load_url_extensions load_url_blacklist
#define load_dns_list       load_url_extensions

extern bool init_dns_hash_table();
extern bool init_reflect_url_hash_table(url_hash_table **out);
extern bool init_url_extensions(url_hash_table **out);

extern bool load_ns_list(const char * file_dirname);
extern ns_node *ns_list ;

#endif 

