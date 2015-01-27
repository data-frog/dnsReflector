#include <assert.h>

#include "hostfilter.h"

#ifndef XFG_RFL
#define log_error(level, data, fmt, ...)	fprintf(stderr, data" "fmt"\n", ##__VA_ARGS__)
#else
#include "global.h"
#define log_error	xLog_R_master
#endif

#define HOST_FILTER_ECOM 	0x1
#define HOST_FILTER_ALL		0x2
#define HOST_FILTER_STATIC	0x4

#define HOSTFILTER_HASHPTR_BIT	0x4
#define HOSTFILTER_ECOM_BIT		0X1
#define HOSTFILTER_STATIC_BIT	0x2

#define update_flag(oflag, nflag)	(oflag) |= (nflag)

#ifdef DEVELOP
#define log_dev(indent, fmt, ...)	do{	\
	int __i = 0;	\
	for(__i = 0; __i != (indent); __i++) printf("\t");	\
	printf("DEV: "fmt"\n", __VA_ARGS__);	\
}while(0)
#else
#define log_dev(indent, fmt, ...)	;
#endif

int
host_filter_eltcmp(const void *a, const void *b){
	host_filter_elt_t *one, *two;
	one = (host_filter_elt_t *)a;
	two = (host_filter_elt_t *)b;

	return ngx_dns_strcmp(one->key.data, two->key.data);
}

int
host_filter_array_init(host_filter_array_t *self){
	ngx_uint_t		asize = 16387;

	self->hsize = 16387;
	self->temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, NULL);
	self->pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, NULL);
	if(self->temp_pool == NULL || self->pool == NULL){
		log_error(RUN_ERRO, "HOSTFILTER", "failed to create pool %s", strerror(errno));
		return 1;
	}

	if(ngx_array_init(&self->hosts, self->temp_pool, asize, \
				sizeof(host_filter_elt_t)) != NGX_OK){
		return NGX_ERROR;
	}
	
	self->hosts_hash = ngx_pnalloc(self->temp_pool, self->hsize * sizeof(ngx_array_t));
	if(self->hosts_hash == NULL) return NGX_ERROR;

	return NGX_OK;
}

int
host_filter_array_addkey(host_filter_array_t *self, u_char *key, size_t len, void *value){
	ngx_array_t 	*elems = &self->hosts, *keys;
	host_filter_elt_t	*elem;
	ngx_str_t		*names;
	ngx_uint_t	flag, k, name_len;
	size_t	skip;

	/* variable used to convert key */
	u_char 	*p;
	size_t	l = 0, n = 0;
	ngx_int_t i=0;

	if(*key == '*' && *(key + 1) == '.'){
		skip = 2;
		flag = HOST_FILTER_ECOM;
	}else if(*key == '*'){
		skip = 1;
		flag = HOST_FILTER_ALL;
	}else{
		skip = 0;
		flag = HOST_FILTER_STATIC;
	}
	
	len -= skip;	
	k = ngx_hash_key(&key[skip], len);
	k = k % self->hsize;

	/* check if there has an duplicate key */
	names = self->hosts_hash[k].elts;
	name_len = self->hosts_hash[k].nelts;
	if(names){
		for(i = 0; i < name_len; i++){
			if(names[i].len != len) continue;

			if(ngx_strncmp(names[i].data, key + skip, len) ==0) return NGX_BUSY;
		}
	}else{
		if(ngx_array_init(&self->hosts_hash[k], self->temp_pool, 4, \
					sizeof(ngx_str_t)) != NGX_OK){
			return NGX_ERROR;
		}
	}

	/* add into filter array for duplicate check */
	keys = &self->hosts_hash[k];
	if((names = ngx_array_push(keys)) == NULL){
		return NGX_ERROR;
	}
	if((names->data = ngx_pnalloc(self->temp_pool, len)) == NULL){
		return NGX_ERROR;
	}
	ngx_memcpy(names->data, key + skip, len);
	names->len = len;

	/* conver example.com to com.example'\0' */
	if((p = ngx_pnalloc(self->temp_pool, len + 1)) == NULL){
		return NGX_ERROR;
	}
	for(i = len - 1; i > -1; i--){
		if(names->data[i] == '.'){
			ngx_memcpy(p + n, &names->data[i + 1], l);
			n += l;
			p[n++] = '.';
			l = 0;
			continue;
		}
		if(i == 0){
			l++;
			ngx_memcpy(p + n, names->data, l);
			n += l;
			continue;
		}
		l++;
	}
	p[n] = '\0';

	/* add into host_filter */
	if((elem = ngx_array_push(elems)) == NULL){
		return NGX_ERROR;
	}
	elem->flag = flag;
	elem->value = value;
	elem->key.data = p;
	elem->key.len = len;
	elem->key_hash = 0;

	return NGX_OK;
}

int
#ifdef DEVELOP
host_filter_init(ngx_hash_init_t *hinit, host_filter_elt_t *names, ngx_uint_t nelts, int indent){
#else
host_filter_init(ngx_hash_init_t *hinit, host_filter_elt_t *names, ngx_uint_t nelts){
#endif
	host_filter_t	*hf;
	ngx_hash_init_t	h;
	ngx_array_t curr_names, next_names;
	ngx_hash_key_t *cname;
	host_filter_elt_t *nname;
	ngx_int_t n, len, dot_len, have_dot, j;

#ifdef DEVELOP
	ngx_int_t i;
#endif
	uint32_t	flag;

	if(ngx_array_init(&curr_names, hinit->temp_pool, nelts, sizeof(ngx_hash_key_t)) 
			!= NGX_OK){
		return NGX_ERROR;
	}
	if(ngx_array_init(&next_names, hinit->temp_pool, nelts, sizeof(host_filter_elt_t)) 
			!= NGX_OK){
		return NGX_ERROR;
	}

	for(n = 0; n != nelts; n = j){
		flag = 0;
		have_dot = 0;
		len = 0;
		dot_len = 0;
		while(len < names[n].key.len){
			if(names[n].key.data[len] == '.'){
				have_dot = 1;
			   	break;
			}
			len++;
		}
		
		cname = ngx_array_push(&curr_names);
		if(cname == NULL){
			return NGX_ERROR;
		}
		cname->key.data = names[n].key.data;
		cname->key.len = len;
		cname->key_hash = hinit->key(cname->key.data, cname->key.len);
		cname->value = names[n].value;
		update_flag(flag, (names + n)->flag);

		log_dev(indent, "cname=%p cname.data=%.*s cname.key_hash=%u flag=%u", 
				cname, (int)cname->key.len, cname->key.data, cname->key_hash, flag);

		dot_len = len + 1;
		if(have_dot) len++;

		next_names.nelts = 0;
		if(len != names[n].key.len){
			if((nname = ngx_array_push(&next_names)) == NULL){
				return NGX_ERROR;
			}
			nname->key.data = names[n].key.data + len;
			nname->key.len = names[n].key.len - len;
			nname->key_hash = 0;
			nname->value = names[n].value;
			nname->flag = names[n].flag;

			log_dev(indent, "nname.data=%.*s nname.key_hash=%u flag=%u", 
					(int)nname->key.len, nname->key.data, nname->key_hash, flag);
		}

		for(j = n + 1; j < nelts; j++){
			if(strncmp((const char *)cname->key.data, (const char *)names[j].key.data, len) != 0) break;
			if(have_dot == 0 && names[j].key.len > len && \
					names[j].key.data[len] != '.')	break;
			
			if((nname = ngx_array_push(&next_names)) == NULL){
				return NGX_ERROR;
			}
			nname->key.data = names[j].key.data + dot_len;
			nname->key.len = names[j].key.len - dot_len;
			nname->value = names[j].value;
			nname->key_hash = 0;
			nname->flag = names[j].flag;
			update_flag(flag, names[j].flag);

			log_dev(indent, "nname.data=%.*s  nname.key_hash=%u flag=%u", 
					(int)nname->key.len, nname->key.data, nname->key_hash, flag);
		}

		flag = names[n].flag;
		log_dev(indent, "len(next_names)=%u flag=%u", next_names.nelts, flag);
		if(next_names.nelts){
			h = *hinit;
			h.hash = NULL;

#ifdef DEVELOP
			if(host_filter_init(&h, (host_filter_elt_t *)next_names.elts, next_names.nelts, indent + 1) != NGX_OK) return NGX_ERROR;
#else
			if(host_filter_init(&h, (host_filter_elt_t *)next_names.elts, next_names.nelts) != NGX_OK) return NGX_ERROR;
#endif

			hf = (host_filter_t *)h.hash;

			if(len == names[n].key.len){
				hf->value = names[n].value;

				if((names[n].flag & HOST_FILTER_STATIC) && (names[n].flag & HOST_FILTER_ECOM)){
					log_dev(indent, "invalid flag in =%u", names[n].flag);
					assert(0);
				}

				if(names[n].flag == HOST_FILTER_ECOM){
					cname->value = (void *)((uintptr_t)hf | HOSTFILTER_ECOM_BIT);
				}
				if(names[n].flag == HOST_FILTER_STATIC){
					cname->value = (void *)((uintptr_t)hf | HOSTFILTER_STATIC_BIT);
				}
				cname->value = (void *)((uintptr_t)cname->value | HOSTFILTER_HASHPTR_BIT);
			}else{
				cname->value = (void *)((uintptr_t)hf | HOSTFILTER_HASHPTR_BIT);
			}

		}else{
			if(flag != HOST_FILTER_STATIC && flag != HOST_FILTER_ECOM && flag != HOST_FILTER_ALL){
				log_dev(indent, "invalid flag=%u", flag);
			   	assert(0);
			}
			
			if(flag == HOST_FILTER_ECOM) cname->value = \
				(void *)((uintptr_t)names[n].value | HOSTFILTER_ECOM_BIT);
			if(flag == HOST_FILTER_STATIC) cname->value = \
				(void *)((uintptr_t)names[n].value | HOSTFILTER_STATIC_BIT);
		}
	}

#ifdef DEVELOP
	cname = (ngx_hash_key_t *)curr_names.elts;
	for(i = 0; i != curr_names.nelts; i++){
		log_dev(indent, "PUSH_HASH %.*s %p", (int)cname[i].key.len, cname[i].key.data, cname[i].value);
	}
#endif

	if(ngx_hash_init(hinit, (ngx_hash_key_t *)curr_names.elts, curr_names.nelts) != NGX_OK)	return NGX_ERROR;

	return NGX_OK;
}

void *
host_filter_find(host_filter_t *self, u_char *key, size_t len){
	ngx_uint_t n, i, k;
	host_filter_t *hf = self;
	uintptr_t	flag;
	int symbol;	//whether the previous flag is type HOSTFILTER_STATIC_BIT
	void *value;
	while(1){
		n = len;
		while(n){
			if(key[n - 1] == '.') break;
			n--;
		}

		k = 0;
		for(i = n; i < len; i++) k += ngx_hash(k, key[i]);
		
		value = ngx_hash_find(&hf->hash, k, key + n, len - n);
		flag = (uintptr_t)value;
		log_dev(0, "%.*s <=> %p\tflag:%lu", (int)(len - n), key + n, value, flag);

		if(value){
			if(flag & HOSTFILTER_HASHPTR_BIT){
				if(n == 0){
					if(flag & HOSTFILTER_ECOM_BIT) return NULL;

					hf = (host_filter_t *)(flag & ~7);
					return hf->value;
				}

				hf = (host_filter_t *)(flag & ~7);
				len = n - 1;
				symbol = (flag & HOSTFILTER_STATIC_BIT) ? 1: 0;
				continue;
			}

			if(n == 0){
				return (flag & HOSTFILTER_ECOM_BIT) ? NULL: (void *)(flag & ~7);
			}

			return (flag & HOSTFILTER_STATIC_BIT) ? NULL: (void *)(flag & ~7);
		}

		return (symbol) ? NULL: hf->value;
	}
	assert(0);
}
/*
void *
host_filter_find(host_filter_t *self, u_char *key, size_t len){
	ngx_uint_t n = len, i, k;
	host_filter_t *hf;
	uintptr_t	flag;
	void *value;
	while(n){
		if(key[n - 1] == '.') break;
		n--;
	}

	k = 0;
	for(i = n; i < len; i++) k += ngx_hash(k, key[i]);

	value = ngx_hash_find(&self->hash, k, key + n, len - n);
	flag = (uintptr_t)value;
	log_dev(0, "%.*s <=> %p\tflag:%lu", (int)(len - n), key + n, value, flag);

	if(value){
		if(flag & HOSTFILTER_HASHPTR_BIT){
			if(n == 0){
				if(flag & HOSTFILTER_ECOM_BIT) return NULL;
				//if((uintptr_t)value & HOSTFILTER_STATIC_BIT) return NULL;

				hf = (host_filter_t *)(flag & ~7);
				return hf->value;
			}

			hf = (host_filter_t *)(flag & ~7);
			value = host_filter_find(hf, key, n - 1);

			if(value != NULL) return value;
			
			return (flag & HOSTFILTER_STATIC_BIT) ? NULL: hf->value;
		}
		
		if(n == 0){
			if(flag & HOSTFILTER_ECOM_BIT) return NULL;
			return value;
		}

		if(flag & HOSTFILTER_STATIC_BIT) return NULL;

		return value;
	}

	return self->value;
}*/
