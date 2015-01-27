#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <assert.h>
#include <openssl/md5.h>
#include "urlmatch.h"
#include "loadconf.h"
#include "loadrsc.h"
#include "iniparser.h"
#include "pkt_process.h"

url_hash_table * reflect_dns_table = NULL ;
unsigned char g_resource_md5[16];

ns_node *ns_list = NULL;
int ns_count = 0 ;
void domain_addr_pair_init(domain_addr_pair *p)
{
	assert(NULL!=p);
	memset(p->url,0,sizeof(p->url));
	memset(p->reflect_addr,0,sizeof(p->reflect_addr));
	p->next = NULL;
}

static int STRINGtoint(char *str)
{
        int i = 0;
        int len = strlen(str);
        int sum = 0;
        for(; i < len; ++i)
        {
                sum = sum * 10 + str[i] - '0';
        }
        return sum;
}

static int iptoint(char *ip)
{
	char *p = ip;
	char *q;
	int num = 0;
	int i = 0;

	while((q = strchr(p, '.')) != NULL)
	{
		*q = 0;
		num += (STRINGtoint(p)&0xff) << (i*8);
		p = q + 1;
		++i;
	}
	num += (STRINGtoint(p)&0xff) << (i*8);
	return num;
}

bool load_ns_list(const char * file_dirname)
{  
	FILE * filp = NULL;  
	ns_node * work = NULL;  
	char str[1024];  
	int j = 0, ilen = 0 ; 
   	bool has_space ;	
	int t; 
	char * s;
	char * sname ;
	char * sip ;
	char * stemp ;

	if(NULL == file_dirname || strlen(file_dirname) <= 1)
	{	
		printf("The domain list dirname is invalid.\n");
		return false ;
	}
/*	
	cache_ds = kmem_cache_create( "cache_dnsl_XXX" , sizeof( ns_node ) , 0, SLAB_HWCACHE_ALIGN, NULL , NULL ) ;
	if( !cache_ds )
	{
		printf("No mem when load domain list.\n");
		return false;
	}
*/
	filp = fopen(file_dirname, "r");
	if( !filp )	
	{
		printf("Open %s failed.\n", file_dirname);
		return false;  
	}

	printf("filp_opened %s \n", file_dirname);
	while(!feof(filp)) 
	{
		memset(str,0,sizeof(str));
		fgets(str, sizeof(str)-1, filp);
		
		{  
			// skip comments line
			if( str[0] == '#' )
			{
				continue ;
			}
			sname = str ;
		
			// The first segment : domain 
			s = strchr(str,' ');
			if( s ) 
			{
				*s = 0 ;	
				s ++ ;
				sip = s ;	
			}
			else
			{
				printf("Invalid line in domain list , No ip inside: [%s]\n" , str) ;
				continue ;
			}

			// check domain name 
			if( strlen(sname) < 2 || strlen(sname) >= DOMAIN_MAX_LEN )
			{
				printf("Invalid line in domain list , Too long domain : [%s]\n" , str) ;
				continue ;
			}

			// Skip the space in end
			j = 0 ;
			has_space = false ;
			for( ; j<strlen(sip); j++)
			{
				if( *(sip+j) == ' ')
				{
					*(sip+j) = 0 ;
					break; 
				}
			}
		
			if(!strlen(sip))
				continue ;

			work = (ns_node *)malloc(sizeof(ns_node));
			if(work == NULL)
			{
				printf("malloc dns node failed.\n");
				continue ; 
			}
			memcpy(work->name , sname, strlen(sname) + 1 ); // + 1 : the end 0
			
			j = 0 ;
			work->server_cnt = 0;  
			work->addrs_head = NULL;  
			has_space = false ;
			ilen = strlen(sip);
			stemp = sip ;
			
			addr_list * last_one = NULL ;		
	
			for( ; j < ilen ; j++)
			{	
				if( ';' == *(sip+j)  )	
				{	
					if(';' == *(sip+j))
						 *(sip+j) = 0 ;
					t = iptoint(stemp) ;

					{
						addr_list * temp_node = (addr_list *)malloc(sizeof(addr_list)); 
						if( temp_node == NULL)
						{   
							printf("kmalloc node in addr_list in dns node failed.\n");
							continue ;
						}
						temp_node->data = t;  
						temp_node->next = work->addrs_head ;
						if( NULL == last_one )
							last_one = temp_node ;
						
						work->addrs_head = temp_node ;	
						work->server_cnt ++ ;
						last_one->next = work->addrs_head ;
					}
					
					if( j != ilen - 1  ) 
						stemp = sip + j + 1;
				}
			}	
			work->now = work->addrs_head ;
			ns_count ++ ;
		
			work->next = ns_list ;
			ns_list = work ;
		}  
		
	}  

	printf("domain name count : %d \n",ns_count);

	if(filp)
		fclose(filp);
	return true;  
}

int get_max_extension_len(const domain_addr_pair *addr_pair_list_head)
{
	int ret = 0 ;
	int t = 0 ;
	const domain_addr_pair * item = addr_pair_list_head ;
	for(;NULL!=item;item=item->next)
	{	
		t = strlen(item->url);
		if( t > ret )
			ret = t;
	}
	return ret ;
}

bool load_url_pair(const char *filename,domain_addr_pair **pdomain_addr_pair_list,const domain_addr_pair *black_list,int* pnum )
{
	assert(NULL==*pdomain_addr_pair_list);
	assert(NULL!=filename);
	assert(NULL!=pnum);
	bool ret = true ;
	*pnum = 0 ; 
	char buf[MAX_LINE_LEN] ;
	domain_addr_pair *next = NULL ;
	
	FILE *fp = fopen(filename, "r");
   	if (!fp) 
	{
 		fprintf(stderr, "Cann't open %s\n", filename);
        return true ;
    }
	
	while(!feof(fp)) 
	{
		int len1,len2;
		
	 	memset(buf,0,sizeof(buf));
		fgets(buf, sizeof(buf)-1, fp);

		// skip the spaces at begin and at end .
		char *pbegin = buf ;
		for(;*pbegin == ' ';pbegin++);		
		char *pend = pbegin+strlen(pbegin)-1;
		for(;(*pend==' '||*pend=='\t'||*pend=='\r'||*pend=='\n')&&pend>pbegin;pend--)*pend=0;
		
		char *p1 = strchr(pbegin,' ') ;
		if(NULL==p1) continue ;
		len1 = p1-pbegin ;
		if(len1 >= MAX_PAYLOAD_LEN ) continue;

		char *p2 = strrchr(pbegin,' '); 
		assert(p2>=p1);
		len2 = pend-p2;
 		if(len2 >= MAX_PAYLOAD_LEN ) continue;

		for(;p1<p2;p1++)
		{
			if(' '!=*p1)
			{
				fprintf(stderr,"Skip the line %s , in config file %s .\n",buf,filename);
				continue;
			}
		}

		// filter by the black list 
		bool is_black = false ;
		const domain_addr_pair * item = black_list;
		for( ; NULL!=item ; item=item->next )
		{	
			int black_len = strlen(item->url);
			if( black_len > len1 ) continue ;
			if( 0 == strncmp(item->url, pbegin,black_len) )
			{
				is_black = true; 
				break;
			}
		}
 		if(is_black)  continue; 
	
		
		domain_addr_pair * temp = malloc(sizeof(domain_addr_pair));
		if( NULL == temp )
		{
			fprintf(stderr,"Cann't allocate memory in load_url_pair().\n");
			ret = false ;
			goto exit ;
		}
		domain_addr_pair_init(temp);
		strncpy(temp->url,pbegin,len1);
		strncpy(temp->reflect_addr,p2+1,len2);

		if( NULL == next )
		{
			*pdomain_addr_pair_list = temp ;
			next = *pdomain_addr_pair_list ;
		}
		else
		{
			next->next = temp ;
			next = temp ;
		}
		++ (*pnum) ; 
    }	

exit :
	if(NULL!=fp)
		fclose(fp);
	return ret;
}

void destroy_url_pair(domain_addr_pair *pdomain_addr_pair_list)
{
	if(NULL==pdomain_addr_pair_list)
		return ;
	domain_addr_pair * t = pdomain_addr_pair_list;
	while(NULL!=t)
	{
		domain_addr_pair * t1 = t;
		t = t->next ;
		free(t1);
	}
}

bool load_url_blacklist(const char *filename,domain_addr_pair **pdomain_addr_pair_list,int* pnum)
{
	assert(NULL==*pdomain_addr_pair_list);
	assert(NULL!=filename);
	assert(NULL!=pnum);
	bool ret = true ;
	*pnum = 0 ; 
	char buf[MAX_PAYLOAD_LEN] ;
	domain_addr_pair *next = NULL ;

	FILE *fp = fopen(filename, "r");
	if (!fp) 
	{	
		// The file is not necessary 
		fprintf(stderr, "Can't open %s\n", filename);
		return true;
	}

	while(!feof(fp)) 
	{
		memset(buf,0,sizeof(buf));
		fgets(buf, sizeof(buf)-1, fp);

		// skip the spaces at begin and at end .
		char *pbegin = buf ;
		for(;*pbegin == ' ';pbegin++);		
		char *pend = pbegin+strlen(pbegin)-1;
		for(;(*pend==' '||*pend=='\t'||*pend=='\r'||*pend=='\n')&&pend>pbegin;pend--)*pend=0;

		if(!strlen(pbegin)) continue;
		domain_addr_pair * temp = malloc(sizeof(domain_addr_pair));
		if( NULL == temp )
		{
			fprintf(stderr,"Cann't allocate memory.\n");
			ret = false ;
			goto exit ;
		}
		domain_addr_pair_init(temp);
		strncpy(temp->url,pbegin,strlen(pbegin));

		if( NULL == next )
		{
			*pdomain_addr_pair_list = temp ;
			next = *pdomain_addr_pair_list ;
		}
		else
		{
			next->next = temp ;
			next = temp ;
		}
		++ (*pnum) ; 
	}	

exit :
	if(NULL!=fp)
		fclose(fp);
	return ret;
}

bool init_dns_hash_table( )
{	
	const char * dns_conf = DNS_LIST_NAME ;
	printf("load dns_conf : %s\n", dns_conf);
	dns_hash_table_init( g_dns_hash_table );

	load_ns_list(dns_conf);

	if(ns_count)
	{
		printf("ns_count %d\n", ns_count);	
		g_dns_hash_table = (new_dns_hash_table *)malloc(sizeof(new_dns_hash_table)); //, GFP_ATOMIC);
		if(NULL == g_dns_hash_table)
		{
			printf("malloc dns_hash_table failed.\n");
			return false ;
		}

		if( !dns_hash_table_create
				( ns_list , ns_count, g_dns_hash_table ) )
		{
			return  false  ;
		}
	}

	return true ;
}

bool init_reflect_url_hash_table(url_hash_table **out)
{
	int url_num,black_num ; 
	domain_addr_pair *blackurl_list = NULL;
	domain_addr_pair *whiteurl_list = NULL;

	if(!load_url_blacklist(IGNORED_URL_LIST_NAME,&blackurl_list,&black_num))
	{
		fprintf(stderr,"Can't load ignored url list(%s).\n",IGNORED_URL_LIST_NAME);
		return false ;
	}

	if(!load_url_pair(URL_LIST_NAME,&whiteurl_list,blackurl_list,&url_num))
		return false;
	
	assert(NULL == *out);
	*out = (url_hash_table *)malloc(sizeof(url_hash_table));
	if(!url_hash_table_create(whiteurl_list, url_num, *out))
		return false ;
	if(isdebug)
	{
		char *name = "url_hash_table";
		dump_hash_table(*out,name);
	}
	destroy_url_pair(whiteurl_list);
	destroy_url_pair(blackurl_list);
	return true ;
}

bool init_url_extensions(url_hash_table **out)
{
	int num ; 
	domain_addr_pair *extension_list = NULL;

	if(!load_url_extensions(URL_EXT_LIST_NAME,&extension_list,&num))
		return false;

	// optimization : get the max extensinos length 
	max_extension_len = get_max_extension_len(extension_list);
	printf("max_extension_len : %d\n",max_extension_len);
	assert(NULL == *out);
	*out = (url_hash_table *)malloc(sizeof(url_hash_table));
	if(!url_hash_table_create(extension_list, num,*out))
		return false ;
	
	if(isdebug)
	{
		char *name = "url_extensions_hash_table";
		dump_hash_table(g_url_extensions_hash_table,name);
	}

	destroy_url_pair(extension_list);
	return true ;
}


