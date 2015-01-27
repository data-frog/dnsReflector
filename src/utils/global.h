#ifndef __REFLACTOR_GLOBAL_H__
#define __REFLACTOR_GLOBAL_H__
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h> 
#include <libnet.h> 
#include "packet.h"

#ifndef bool
#define bool int
#endif 

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#define GET_URL            "GET /"
extern libnet_t* net_t;
extern int reflactor_thread_count;
extern int keep_alive_time;
extern volatile bool quit ;
extern char *out_device;
extern int http_sqs_capacity;

extern volatile long total_http_pkt_count  ;
extern volatile long total_dns_pkt_count ;
extern volatile long reflected_http_pkt_count  ;
extern volatile long reflected_dns_pkt_count ;

#define REFLECT_PID         "/var/run/dnsReflector.pid"
#define REFLECT_PDIR		"/var/run/"

#define REFLECTORVERSION	"1.2" //MYREFLECTOR_VERSION_1165a2836bab4d69b685fdba1876e795"
extern int datalink;
extern int isdebug;
#define debug(format...) if (isdebug !=0) printf (format)

#define REFLECTOR_WATCH_FILE "/usr/local/dnsReflector/etc/.refwatch"
//RESOURCE 
#define DNS_LIST_NAME 		   "/usr/local/dnsReflector/etc/dns.list"
#define URL_LIST_NAME 		   "/usr/local/dnsReflector/etc/url.list"
#define IGNORED_URL_LIST_NAME  "/usr/local/dnsReflector/etc/url_ignored.list"
#define URL_EXT_LIST_NAME 	   "/usr/local/dnsReflector/etc/url_extension.list"
#define BLACK_SRC_LIST_NAME    "/usr/local/dnsReflector/etc/ip_black.list"
#define WHITE_SRC_LIST_NAME    "/usr/local/dnsReflector/etc/ip_white.list"
#define CONFIG_NAME 	   	   "/usr/local/dnsReflector/etc/dnsReflector.conf"
#define LOG_DIR  			   "/data/proclog/log/dnsReflector/"

#define REFLECTOR_PROC_NAME "dnsReflector"

#define MAX_CONFIG_LEN  1024*128
#define MAX_DIRNAME_LEN 1024
#define REFLECTOR_BPFILTER "greater 68"
#define MAX_LINE_LEN 2048

#define MAX_IPV4_LEN 15

extern char *device;
extern char *bpfilter ;
extern char squid_ip[MAX_IPV4_LEN + 1] ;
extern u_int32_t isquid_ip;
#define MAX_WORK_THREAD_NUM 32
#define WATCH_INTEVAL 5*60

#define SIG_RELOAD_DNS_LIST SIGRTMIN+6
#define SIG_RELOAD_URL_LIST SIGRTMIN+7
#define SIG_RELOAD_URL_EXT  SIGRTMIN+8

#endif
 
