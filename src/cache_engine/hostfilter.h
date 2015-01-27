#ifndef XFG8_RFL_EEIWANT_HOSTFILTER_H
#define XFG8_RFL_EEIWANT_HOSTFILTER_H

#include <ngx_core.h>
#include <ngx_config.h>

typedef struct{
	ngx_hash_t hash;
	void *value;
}host_filter_t;


typedef struct{
	ngx_str_t 	key;
	ngx_uint_t	key_hash;
	void 		*value;
	uint32_t	flag;
}host_filter_elt_t;


typedef struct{
	ngx_uint_t	hsize;
	ngx_pool_t	*temp_pool;
	ngx_pool_t	*pool;

	ngx_array_t	hosts;
	ngx_array_t *hosts_hash;
}host_filter_array_t;

/*#define DEVELOP*/
#ifdef DEVELOP
int host_filter_init(ngx_hash_init_t *hinit, host_filter_elt_t *names, ngx_uint_t nelts, int indent);
#else
int host_filter_init(ngx_hash_init_t *hinit, host_filter_elt_t *names, ngx_uint_t nelts);
#endif

void * host_filter_find(host_filter_t *self, u_char *key, size_t len);

int host_filter_array_init(host_filter_array_t *self);
int host_filter_array_addkey(host_filter_array_t *self, u_char *key, size_t len, void *value);


int host_filter_eltcmp(const void *a, const void *b);
#endif
