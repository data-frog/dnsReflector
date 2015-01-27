#include <stdio.h>

#include "hostfilter.h"
#include "hostlist.h"
#include "libngx_init.h"
#ifndef XFG_RFL
#define log_error(level, a, fmt, ...) fprintf(stderr, a" "fmt"\n", ##__VA_ARGS__)
#else
#include "global.h"
#define log_error xLog_R_master
#endif

#define HOSTLIST_IN	(int *)0x100
#define HOSTLIST_RET_OK		0
#define HOSTLIST_RET_EMPTY	1
#define HOSTLIST_RET_FAIL	2

static host_filter_t *wfilter, *bfilter;
static ngx_hash_init_t h;
int wlist_used, blist_used;
int max_size = 102, bucket_size = 128;

static int build_filter_from_file(const char *path, ngx_hash_init_t *h);

int
hostlist_init(const char *wlist_path, const char *blist_path){
	int ret = 1, r;

	if(libngx_get_cacheline() == 0){
		libngx_init();
	}
	memset(&h, 0, sizeof(ngx_hash_init_t));

	if(access(wlist_path, R_OK) != 0){
		log_error(RUN_INFO, "HOSTLIST", "wlist %s not exist", wlist_path);
		wlist_path = NULL;
	}

	if(access(blist_path, R_OK) != 0){
		log_error(RUN_INFO, "HOSTLIST", "blist %s not exist", blist_path);
		blist_path = NULL;
	}

	wlist_used = 0;
	blist_used = 0;
	if(wlist_path == NULL && blist_path == NULL){
		return 0;
	}

	h.key = ngx_hash_key_lc;
	h.max_size = max_size;	
	h.bucket_size = bucket_size;
	h.pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, NULL);
	h.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, NULL);
	h.hash = NULL;

	if(h.pool == NULL || h.temp_pool == NULL){
		log_error(RUN_ERRO, "HOSTLIST", "can not create ngx_pool");
		goto exit;
	}

	if(wlist_path != NULL){
		r = build_filter_from_file(wlist_path, &h);
		if(r == HOSTLIST_RET_FAIL){
			goto exit;
		}else if(r != HOSTLIST_RET_EMPTY){
			wlist_used = 1;
			wfilter = (host_filter_t *)h.hash;
			h.hash = NULL;
		}
	}
	
	if(blist_path != NULL){
		r = build_filter_from_file(blist_path, &h);
		if(r == HOSTLIST_RET_FAIL){
			goto exit;
		}else if(r != HOSTLIST_RET_EMPTY){
			blist_used = 1;
			bfilter = (host_filter_t *)h.hash;
			h.hash = NULL;
		}
	}
	
	ret = 0;
	ngx_destroy_pool(h.temp_pool);
	h.temp_pool = NULL;
	return ret;

exit:
	if(h.temp_pool){
		ngx_destroy_pool(h.temp_pool);
		h.temp_pool = NULL;
	}

	if(h.pool){
	   	ngx_destroy_pool(h.pool);
		h.pool = NULL;
	}

	return ret;
}

void
hostlist_destroy(){
	if(h.pool) ngx_destroy_pool(h.pool);
	h.pool = NULL;
}

static int
build_filter_from_file(const char *path, ngx_hash_init_t *hinit){
	FILE *fp = NULL;
	host_filter_array_t keys;
#define HOSTLIST_TMPBUF_LEN		256
	char tmp[HOSTLIST_TMPBUF_LEN];
	size_t tmp_len;
	int ret = HOSTLIST_RET_FAIL, count = 0;
	
	host_filter_array_init(&keys);
	fp = fopen(path, "r");
	if(fp == NULL){
		log_error(RUN_ERRO, "HOSTLIST", "can not open %s %s", path, strerror(errno));
		return HOSTLIST_RET_FAIL;
	}

	while(fgets(tmp, HOSTLIST_TMPBUF_LEN - 1, fp)){
		if(tmp[0] == '#' || tmp[0] == '\n' || tmp[0] == '\0') continue;
		count++;
		tmp_len = strlen(tmp);
		if(tmp[tmp_len - 1] == '\n'){
			tmp[tmp_len - 1] = '\0';
		}
		tmp_len--;

		if(host_filter_array_addkey(&keys, (u_char *)tmp, tmp_len, HOSTLIST_IN) == NGX_BUSY){
			log_error(RUN_INFO, "HOSTLIST", "DUPLICATE_KEY %s", tmp);
		}
	}

	if(count == 0) return HOSTLIST_RET_EMPTY;

	ngx_qsort(keys.hosts.elts, keys.hosts.nelts, sizeof(host_filter_elt_t), host_filter_eltcmp);

#ifdef DEVELOP
	if(host_filter_init(hinit, (host_filter_elt_t *)keys.hosts.elts, keys.hosts.nelts, 0) != NGX_OK){
#else
	if(host_filter_init(hinit, (host_filter_elt_t *)keys.hosts.elts, keys.hosts.nelts) != NGX_OK){
#endif
		log_error(RUN_ERRO, "HOSTLIST", "failed init host_filter_t");
		goto exit;
	}

	ret = 0;

exit:
	return ret;
}

int
hostlist_pass(unsigned char *key, size_t len){
	unsigned char white = 0, black = 0;
	white = (wlist_used) ? host_filter_find(wfilter, key, len) == HOSTLIST_IN : 1;

	if(white == 0){
		return 0;
	}

	black = (blist_used) ? host_filter_find(bfilter, key, len) == HOSTLIST_IN : 0;

#ifdef TEST
	printf("%s %s %s\n", key, (white == 1) ? "in_white": "not_in_white",
			(black == 1) ? "in_black": "not_in_black");
#endif
	return white & !black;
}

