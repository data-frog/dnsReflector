#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <openssl/md5.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/inotify.h>
#include "global.h"
#include "loadconf.h"
#include "reflect.h"
#include "http_sqs.h"
#include "ref_time.h"

httpsqs *httpsqs_base = NULL; 
dnssqs *dnssqs_base = NULL; 
int reflactor_thread_count = 1 ;
volatile long reflected_http_pkt_count  = 0 ;
volatile long reflected_dns_pkt_count = 0 ;
const char* salt = "www.data-frog.com" ;

void * dns_reflect_thread_entry(void *arg)
{
	dnssqs * psqs =(dnssqs *)arg ;
	pkt_data  data ;
	bool got = false ;
	while(!quit)
	{
		memset(&data,0,sizeof(data));
		got = httpsqs_pop_front(&data,psqs);
		if(!got)
		{
			usleep(1);
			continue ;
		}
		// printf("handle dns packet .\n");
		++ reflected_dns_pkt_count;
		handle_dns_packet(&data);		
	}
	return((void *)1);
}

void *http_reflect_thread_entry(void *arg)
{	
	httpsqs * psqs =(httpsqs *)arg ;
	pkt_data  data ;
	bool got = false ;
	while(!quit)
	{
		memset(&data,0,sizeof(data));
		got = httpsqs_pop_front(&data,psqs);
		if(!got)
		{
			usleep(1);
			continue ;
		}
		// printf("handle http packet .\n");
		++ reflected_http_pkt_count;
		handle_http_packet(&data);
	}
	return((void *)1);
}

bool create_reflactor_threads( )
{
	// create httpsqs for all threads 	
	int i = 0 ;
	int err = 0 ;
	
	httpsqs_base = (httpsqs *)malloc(reflactor_thread_count*sizeof(httpsqs));
	dnssqs_base = (dnssqs *)malloc(reflactor_thread_count*sizeof(httpsqs));
	if( NULL==httpsqs_base || NULL == dnssqs_base)
	{
		fprintf(stderr,"Can't allocate memory in create_reflactor_threads().\n");
		return false ;
	}
	for(i=0 ; i < reflactor_thread_count; i++)
	{

#if 0
		if( url_reflector )
		{
			httpsqs  *item = httpsqs_base + i;
			httpsqs_init(0,item);
			err = pthread_create(&http_thread_ids[i],NULL,http_reflect_thread_entry,item);	
			if( err != 0 )
			{
				fprintf(stderr,"Can't create http reflect thread.\n");
				return false ;
			}
		}
#endif
		if( dns_reflector )
		{
			httpsqs  *item = dnssqs_base + i;
			httpsqs_init(0,item);		
			err = pthread_create(&dns_thread_ids[i],NULL,dns_reflect_thread_entry,item);	
			if( err != 0 )
			{
				fprintf(stderr,"Can't create dns reflect thread.\n");
				return false ;
			}
		}
	}
	printf("%d reflector threads created .\n", reflactor_thread_count);	
	return true ;	
}

bool compareMd5sum(MD5_CTX md5sum,char *old_crc)
{
    MD5_CTX temp = md5sum;
    unsigned char md[16]; 
    MD5_Final(md,&temp);
    char md5str[33] = {0};
    int i ;
    for(i=0; i<16; i++)
         snprintf(md5str + i*2, 32, "%02x",md[i]);
	
    return (0 == strncmp(md5str,old_crc,32)) ;
}

bool check_authorization(const char*datetime )
{
	size_t i =0 ;

	printf("open %s \n", REFLECTOR_WATCH_FILE);	
	char buf[256] = {0};
	FILE *fp = fopen(REFLECTOR_WATCH_FILE, "r");
   	if (!fp) 
	{
 		fprintf(stderr, "[%s] Cann't open %s\n",datetime, REFLECTOR_WATCH_FILE);
        return false;
    }
	
	int read_len = fread(buf,sizeof(char),sizeof(buf),fp);
	fclose(fp);

	if(32 != read_len)
		return false ;

	MD5_CTX ctx;
	MD5_Init(&ctx);

	MD5_Update(&ctx,salt,strlen(salt));

	struct timeval now;
    gettimeofday(&now,NULL);
    int delta[ ] = {0,600} ;
    for(;i<sizeof(delta)/sizeof(int);i++)
    {
		int num = (now.tv_sec - delta[i]) / 600 ;
    	char str_num[10] = {0};
    	sprintf(str_num,"%d",num);
   
        MD5_CTX temp_md5sum = ctx ;
        MD5_Update(&temp_md5sum,str_num,strlen(str_num));

        bool equal = compareMd5sum(temp_md5sum,buf) ;
		if(equal)
		{
		    printf("[%s]check_authorization() sync with cmu ok.\n",datetime);
            return true;
    	}
	}
    return false ;
}
 
void* watch_thread_entry(void *arg)
{
	int count = 0 ;
	
	while(!quit)
	{
		char datetime[100] = {0};
        time_to_str(datetime, "%Y-%m-%d %H:%M:%S");
		
		if(!check_authorization(datetime)) 
		{
			++count;
			if(count > 2)
			{
				printf("[%s] failed authorization count > 3, quit\n",datetime);
				raise(SIGINT);
			}
		}
		else
		{
			count = 0;
			printf("[%s] Authorization passed, unlink sync file\n",datetime);
			unlink(REFLECTOR_WATCH_FILE);
		}
		sleep(WATCH_INTEVAL);
	}
	pthread_exit((void *)0);
}

bool create_watch_thread( )
{
	int err = pthread_create(&watch_cmu_thread_id,NULL,watch_thread_entry,NULL);	
	if( err != 0 )
	{
		fprintf(stderr,"Can't create cmu watch thread.\n");
		return false ;
	}
	printf("Watch_thread created.\n");
	return true;
}

