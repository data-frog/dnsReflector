#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>
#include "global.h"
#include "pkt_process.h"
#include "http_sqs.h"
#include "ref_time.h"
#include "logger.h"

httpsqs * logsqs_base = NULL;
int keep_alive_time = 10;
pthread_t log_thread_id = 0; 

static int log_need_rotate = false ;
static int log_rotate_delta = 10 * 60 ;

static void alarm_handler(int sig)
{
	log_need_rotate = true ;
	alarm(log_rotate_delta);
}

static bool log_write(const int url_log_stream ,const void *record)
{
	pkt_data *pkt = (pkt_data*)record ;
	u_char *payload = pkt->p; 
	char *p = (char*)&payload[strlen(GET_URL) - 1];
	char *host = NULL ;
	char *range = NULL ;
	domain_addr_pair *dest_url_pair;
	bool ret = true;

	char *url = (char*)p;
	// skip the " \t\012\015" at the initial portion 
	url += strspn(url, " \t\012\015");
	// p is a pointer the first occurrence in " \t\012\015"
	p = strpbrk(url, " \t\012\015");

	if( NULL== p ) // Single line 
		goto exit;
	
	// skip the 206 request including "Range:"
	range = parseRange(p);
	if(NULL != range)
		goto exit;
	
	host = parseHost(p);
	if(host == NULL)
		goto exit;
	*p = '\0';
	
	char *end = strchr(url,'?');
	if(end) *end = 0;

	// Skip reflected request 
	if(0==strcmp(host,squid_ip))
		goto exit;
	
	// Match the extension name 
	char *extension = strrchr(url,'.');
	if( NULL == extension || max_extension_len < strlen(extension+1) )
		goto exit;
	else
	{
		//debug("extension: %s\n",extension);
		dest_url_pair = url_hash_table_find(g_url_extensions_hash_table,extension+1);
		if(NULL==dest_url_pair)
			goto exit;
	}

	char myurl[MAX_PAYLOAD_LEN+100] = {0};
	int pos = snprintf(myurl,sizeof(myurl),"http://%s%s\n",host,url);	
	myurl[pos]='\0';

	// Log
	if( strlen(myurl) != write(url_log_stream,myurl,strlen(myurl)))
		ret = false ;
exit :
	return ret;
}

void * log_thread_entry(void *arg)
{
	dnssqs * psqs =(logsqs *)arg ;
	pkt_data  data ;
	bool got = false ;
	int url_log_stream = 0 , rate_log_stream = 0 ;
	assert(NULL!=psqs);
	long log_http_pkt_count = 0;
	
	//Init url log name .
	char url_log_name[MAX_DIRNAME_LEN] = {0};
	char datetime[100] = {0};
	time_to_str(datetime, "%Y-%m-%d-%H-%M");
	int pos=snprintf(url_log_name,sizeof(url_log_name),"%s/%s-%s",LOG_DIR,"url.list",datetime);
	url_log_name[pos]='\0';

	//Init reflect rate log name .
	char rate_log_name[MAX_DIRNAME_LEN] = {0};
	pos=snprintf(rate_log_name,sizeof(rate_log_name),"%s/%s-%s",LOG_DIR,"reflect.rate",datetime);
	rate_log_name[pos]='\0';
	
	//Open logs 
	url_log_stream = open(url_log_name,O_WRONLY|O_CREAT|O_APPEND);
	if( url_log_stream <= 0 ) 
	{
		fprintf(stderr,"Can't create url log file %s,log thread exit.\n",url_log_name);
		pthread_exit((void *)1);
	}
	rate_log_stream = open(rate_log_name,O_WRONLY|O_CREAT|O_APPEND);
	if( rate_log_stream <= 0)
	{
		fprintf(stderr,"Can't open rate log file %s,log thread exit.\n",rate_log_name);
		pthread_exit((void *)1);
	}
	
	//  settimer for log rotate 
	signal( SIGALRM, alarm_handler );
	alarm(log_rotate_delta);
	
	while(!quit)
	{
		memset(&data,0,sizeof(data));
		got = httpsqs_pop_front(&data,psqs);
		if(!got)
		{
			usleep(1);
			continue ;
		}
		// printf("loop in log_thread_entry .\n");
		if(!log_write(url_log_stream,&data))
		{
			fprintf(stderr,"write log failed .\n");
		}
		++ log_http_pkt_count ;

		// log reflect rate 
		if(log_need_rotate)
		{
			if(url_log_stream>0) close(url_log_stream); 

			//Init url log name .
			char url_log_name[MAX_DIRNAME_LEN] = {0};
			char datetime[100] = {0};
			time_to_str(datetime, "%Y-%m-%d-%H-%M");
			int pos=snprintf(url_log_name,sizeof(url_log_name),"%s/%s-%s",LOG_DIR,"url.list",datetime);
			url_log_name[pos]='\0';
			
			//Open logs 
			url_log_stream = open(url_log_name,O_WRONLY|O_CREAT|O_APPEND);
			if( url_log_stream <= 0 ) 
			{
				fprintf(stderr,"Can't create url log file %s,log thread exit.\n",url_log_name);
				pthread_exit((void *)1);
			}
	
			char rate_line[2000] = {0};
			memset(datetime,0,sizeof(datetime));
			time_to_str(datetime, "%Y-%m-%d(%H:%M:%S)");
	
			snprintf(rate_line,sizeof(rate_line),"%s {http:[total:%ld,reflect:%ld,log:%ld]},{dns:[reflect:%ld,total:%ld]}\r\n",\
				datetime,total_http_pkt_count,\
				reflected_http_pkt_count,log_http_pkt_count,\
				reflected_dns_pkt_count,total_dns_pkt_count);

			if(strlen(rate_line) != write(rate_log_stream,rate_line,strlen(rate_line)))
				return false ;
	
			snprintf(rate_line,sizeof(rate_line),"%s {http:[total:%ld,reflect:%ld,log:%ld]},{dns:[reflect:%ld,total:%ld]} - second line\r\n",\
				datetime,total_http_pkt_count,\
				reflected_http_pkt_count,log_http_pkt_count,\
				reflected_dns_pkt_count,total_dns_pkt_count);

			if(strlen(rate_line) != write(rate_log_stream,rate_line,strlen(rate_line)))
				return false ;

			total_http_pkt_count = 0 ;
			reflected_http_pkt_count = 0 ;
			reflected_dns_pkt_count = 0 ;
			total_dns_pkt_count = 0 ;
			log_http_pkt_count = 0 ;
			log_need_rotate = false ;
		}
	}
	if(url_log_stream>0) close(url_log_stream);
	if(rate_log_stream>0) close(rate_log_stream);
	//httpsqs_clear(psqs);
	pthread_exit((void *)0);
}

bool create_log_thread( )
{
	int err = 0 ;

	logsqs_base = (logsqs *)malloc(sizeof(logsqs));
	if(NULL == logsqs_base)
	{
		fprintf(stderr,"Can't allocate memory in create_log_thread().\n ");
		return false ;
	}

	httpsqs_init(0,logsqs_base);
	err = pthread_create(&log_thread_id,NULL,log_thread_entry,logsqs_base);	
	if( err != 0 )
	{
		fprintf(stderr,"Can't create log thread by pthread_create().\n ");
		return false ;
	}
	return true ;
}

