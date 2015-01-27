#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <assert.h>
#include <openssl/md5.h>
#include "global.h"
#include "urlmatch.h"
#include "loadconf.h"
#include "iniparser.h"
#include "http_sqs.h"

int http_sqs_capacity = DEFAULT_HTTPSQS_CAPACITY;
char *bpfilter = REFLECTOR_BPFILTER;
char *device = NULL ;
char squid_ip[MAX_IPV4_LEN + 1] = {0};
u_int32_t  isquid_ip = 0;
bool dns_reflector = true ;
bool url_reflector = true ;

char conf_crc[33] = {0};

bool parse_config(const char* conf_path)
{
    dictionary *ini ;
    char *t = NULL ;
	bool ret = true; 
    // Open config file.
    ini = iniparser_load(conf_path);
    if (ini==NULL) 
    {
        fprintf(stderr, "Can't load config file: %s\n", conf_path);
        return false;
    }
    
	t = iniparser_getstring(ini, "dnsconf:filter", REFLECTOR_BPFILTER);
	if(strlen(t)){
		bpfilter =  strdup(t);
	}

/*
	t = iniparser_getstring(ini,"reflector:squid_ip",NULL);
	if( NULL==t || !strlen(t) || strlen(t)>15 )
	{
		fprintf(stderr,"No squid_ip in configure,quit.\n");
		ret = false ;
		goto exit ;
	}
	else
	{
		memcpy(squid_ip,t,strlen(t));
	}
	t = iniparser_getstring(ini,"reflector:dns_reflector","on");
	if(strcmp("on",t)) dns_reflector = false; 

	t = iniparser_getstring(ini,"reflector:url_reflector","on");
	if(strcmp("on",t)) url_reflector = false; 
	
	debug("dns_reflector:%d,url_reflector:%d",dns_reflector,url_reflector);	

*/
	if(NULL != ini)
		iniparser_freedict(ini);
    return ret ;

}


