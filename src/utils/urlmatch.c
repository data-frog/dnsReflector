#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "global.h"
#include "packet.h"
#include "urlmatch.h"

#define  get_url_hash_table_node(purl_hash_table,index)  ((url_hash_node *)((purl_hash_table->head)+index))

#define init_url_hash_node(node) 		\
		assert(NULL!=node); \
		(node)->used = false ;\
		memset((node)->data->url,0,sizeof((node)->data->url));\
		memset((node)->data->reflect_addr,0,sizeof((node)->data->reflect_addr));\
		(node)->data->next = NULL ;

static inline void append_dns_response_pair( dns_response_pair * first , dns_response_pair * append);
static inline int url_simple_hash(const char* purl,const int hash_table_capacity)
{
	unsigned int sum=0;
	for(;'\0'!=*purl;purl++)  sum+=(unsigned int)(*purl);
	return (int)(sum % hash_table_capacity);
}

// AP Hash Function
static inline int APHash(const char* purl,const int hash_table_capacity)
{
    unsigned int hash = 0;
    int i;

    for (i=0; *purl; i++)
    {
        if ((i & 1) == 0)
        	hash ^= ((hash << 7) ^ (*purl++) ^ (hash >> 3));
        else
        	hash ^= (~((hash << 11) ^ (*purl++) ^ (hash >> 5)));
    }

    return (int)(hash % hash_table_capacity);
}

static inline int BKDRHash(const char* purl,const int hash_table_capacity)
{
    unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
    unsigned int hash = 0;

    while (*purl)
    {
        hash = hash * seed + (*purl++);
    }

    return (int)(hash % hash_table_capacity);
}


// DJB Hash Function
static inline int DJBHash(const char* purl,const int hash_table_capacity)
{
    unsigned int hash = 5381;

    while (*purl)
    {
        hash += (hash << 5) + (*purl++);
    }

    return (int)(hash % hash_table_capacity);
}

static inline bool append_domain_addr_pair( domain_addr_pair * first , const domain_addr_pair*append )
{
	domain_addr_pair * insert_node = (domain_addr_pair *)malloc(sizeof(domain_addr_pair));
	if(NULL == insert_node)
	{
		fprintf(stderr,"Can't allocate memory in create_hash_table().\n");
		return false ;
	}
	insert_node->next = NULL ;
	strcpy(insert_node->url,append->url);
	strcpy(insert_node->reflect_addr,append->reflect_addr);
	for(; first->next != NULL; first=first->next) ; // printf("append %s\n",first->url);
	first->next = insert_node ;
	return true;
}

void url_hash_table_init(url_hash_table* p_url_hash_table)
{
	p_url_hash_table->head = NULL ;
	p_url_hash_table->num = 0 ;
}

bool url_hash_table_create(const domain_addr_pair* domain_addr_pair_list,const int num,url_hash_table* p_url_hash_table)
{
	int i=0;
	
 	url_hash_node *p_url_hash_node =(url_hash_node*)malloc(num*sizeof(url_hash_node));
	if(NULL == p_url_hash_node)
	{
		fprintf(stderr,"Can't allocate memory in create_hash_table().\n");
		return false ;
	}
	for(i=0;i<num;i++) 
	{
		(p_url_hash_node+i)->data = (domain_addr_pair *)malloc(sizeof(domain_addr_pair));
		if(NULL == (p_url_hash_node+i)->data)
		{
			fprintf(stderr,"Can't allocate memory in create_hash_table().\n");
			return false ;
		}	
		init_url_hash_node( (p_url_hash_node+i) ) ;
	}

	// insert nodes ;
	for(;NULL != domain_addr_pair_list;domain_addr_pair_list=domain_addr_pair_list->next)
	{
		int index = DJBHash(domain_addr_pair_list->url,num) ;
		assert(0<=index&&index<num);
		if( ! (p_url_hash_node+index)->used )
		{
			strcpy((p_url_hash_node+index)->data->url,domain_addr_pair_list->url);
			strcpy((p_url_hash_node+index)->data->reflect_addr,domain_addr_pair_list->reflect_addr);
			(p_url_hash_node+index)->data->next = NULL ;
			(p_url_hash_node+index)->used= true;
		}
		else
		{
			if(!append_domain_addr_pair( (p_url_hash_node+index)->data,domain_addr_pair_list))
				return false ;
			(p_url_hash_node+index)->used = true ; 
		}		
	}
	p_url_hash_table->head = p_url_hash_node ;
	p_url_hash_table->num = num ;
	return true;
}

void collision_info(const url_hash_table* p_url_hash_table )
{
	printf("****************collision_info****************\n");
	printf("hash table size : %d \n",p_url_hash_table->num);
	url_hash_node *node = p_url_hash_table->head;
	int i = 0, used = 0;
	for(; i<p_url_hash_table->num;i++)
		if( (node+i)->used ) 
			used ++ ;
	printf("hash table used : %d \n",used);

	printf("****************collision_end****************\n");
}

domain_addr_pair * url_hash_table_find(const url_hash_table* purl_hash_table,const char* purl)
{
	url_hash_node * dest_hash_node = NULL ;
	if(NULL==purl_hash_table||NULL==purl_hash_table->head) return false ;

	int index = DJBHash(purl,purl_hash_table->num) ;

	dest_hash_node = get_url_hash_table_node(purl_hash_table,index);
	if( ! dest_hash_node->used )
		return NULL ;
	else
	{
		domain_addr_pair * temp = NULL ;
		for( temp=dest_hash_node->data;temp!=NULL;temp=temp->next)
		{
			if( 0 == strcmp(temp->url,purl) )
				return temp ;
		}
	}
	return NULL;
}

#define  get_dns_hash_table_node(pdns_hash_table,index)  ((dns_hash_node **)((pdns_hash_table->head)+index))

dns_response_pair * dns_hash_table_find(const new_dns_hash_table* pdns_hash_table,const char* pdns )
{
	char buf_dns[1024];
	dns_hash_node ** dest_hash_node = NULL ;
	int index ;
	buf_dns[40] = '\0';

	if(!pdns) return NULL ;

	if(NULL==pdns_hash_table||NULL==pdns_hash_table->head)
	{
		return NULL ;
	}

	index = DJBHash(pdns,pdns_hash_table->num) ;
	dest_hash_node = get_dns_hash_table_node(pdns_hash_table,index);
	if( NULL == dest_hash_node )
	{
		return NULL ;
	}
	else
	{
		dns_response_pair * temp = NULL ;
		for( temp= *dest_hash_node ; temp!=NULL ; temp=temp->next )
		{
			if( 0 == strcmp(temp->name,pdns))
			{
				return temp ;
			}
		}
	}
	return NULL;
}

void dump_hash_table( const url_hash_table* purl_hash_table,const char * table_name)
{
	url_hash_node * dest_hash_node = NULL ;
    if(NULL==purl_hash_table||NULL==purl_hash_table->head) 
	{
		printf("hash table '%s' is NULL .\n",table_name);
	}	
	int i = 0 ;
	printf("hash table name :%s\n",table_name);
	printf("*************************************************************\n");
	for(;i<purl_hash_table->num;i++)
    {
	    dest_hash_node = get_url_hash_table_node(purl_hash_table,i);
     	if( ! dest_hash_node->used )
			continue ;
    	else
    	{
        	domain_addr_pair * temp = NULL ;
        	for( temp=dest_hash_node->data;temp!=NULL;temp=temp->next)
        	{
        		printf("url: %s    |   ",temp->url);
			}	
		}
    }	
	printf("*************************************************************\n");
}

void url_hash_table_destroy(url_hash_table* purl_hash_table)
{
	if(NULL == purl_hash_table) return ;
	int i = 0 ;
	if(NULL == purl_hash_table->head || 0 == purl_hash_table->num) return ;
	for(i=0; i< purl_hash_table->num ; i++ )
	{
		url_hash_node * temp = purl_hash_table->head + i ;
		domain_addr_pair * pdata = NULL ;
		for( pdata = temp->data;NULL!=pdata;)
		{
			domain_addr_pair * pdata2 = pdata ;
			pdata = pdata->next ;
			free(pdata2);
		}
	}
	free(purl_hash_table->head);
	purl_hash_table->head = NULL ;
	purl_hash_table->num = 0 ;
	if(purl_hash_table) free(purl_hash_table);
	return;
}

bool url_hash_table_isfree(const url_hash_table* p_url_hash_table)
{ 
	return NULL == p_url_hash_table->head && 0 == p_url_hash_table->num ;
}

void dns_hash_table_init(new_dns_hash_table* p_dns_hash_table)
{
        if(!p_dns_hash_table)
                return ;
        p_dns_hash_table->head = NULL ;
        p_dns_hash_table->num = 0 ;
}

bool dns_hash_table_create(dns_response_pair* dns_response_pair_list,const int list_count ,new_dns_hash_table* p_dns_hash_table)
{
	int i=0, index = 0;
	int num = list_count > 5000000 ? 5000000 : list_count ;
	dns_response_pair*  next = NULL ;
	dns_response_pair*  temp_it = NULL ;
 	dns_hash_node **p_dns_hash_node ;
#if 0
	node_cache = kmem_cache_create( "node_cache" , num * sizeof(dns_hash_node*) , 0, SLAB_HWCACHE_ALIGN, NULL , NULL ) ;
	if( ! node_cache )
	{
		printk("No mem when load dns hash table create.\n");
		return false;
	}
#endif
	//p_dns_hash_node = (dns_hash_node**)kmem_cache_alloc(node_cache,GFP_KERNEL);
	p_dns_hash_table->head = NULL ;
	p_dns_hash_table->num = 0 ;
	p_dns_hash_node = (dns_hash_node**)malloc(  num * sizeof(dns_hash_node*) ); // ,GFP_KERNEL);
	if(NULL == p_dns_hash_node)
	{
		printf("Can't vmalloc memory in create_hash_table(), num : %d.\n", num);
		for(temp_it = dns_response_pair_list; temp_it != NULL; temp_it = temp_it->next )
			free(temp_it);	
		return false ;
	}
	
	for( i=0; i< num ; i++ ) 
		*(p_dns_hash_node+i) = (dns_hash_node *)NULL ;

	// insert nodes ;
	for( ; NULL != dns_response_pair_list ; )
	{
		next = dns_response_pair_list->next;
	
		index = DJBHash(dns_response_pair_list->name, num) ;
		if( NULL == *(p_dns_hash_node+index) )
		{
			*(p_dns_hash_node+index) = dns_response_pair_list ;
			dns_response_pair_list->next = NULL ;
		}
		else
		{
			append_dns_response_pair( *(p_dns_hash_node+index),dns_response_pair_list);
		}	
		
		dns_response_pair_list = next ;	
	}
	p_dns_hash_table->head = p_dns_hash_node ;
	p_dns_hash_table->num = num ;
	return true;
}

static inline void append_dns_response_pair( dns_response_pair * first , dns_response_pair * append )
{
	append->next = NULL ;
	for(; first->next != NULL; first=first->next) ; 
	first->next = append ;
	return ;
}


