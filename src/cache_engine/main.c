#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <libnet.h>
#include <string.h>
#include "global.h"
#include "http_sqs.h"
#include "reflect.h"
#include "http_cap.h"
#include "logger.h"
#include "loadconf.h"
#include "loadrsc.h"
#include "urlmatch.h"
#include "hostlist.h"
#include "pid.h"

#include "libngx_init.h"

volatile bool quit = false ;
libnet_t* net_t=NULL;
int datalink;
int isdebug;

char *out_device = NULL ;
pthread_t http_thread_ids[MAX_WORK_THREAD_NUM] ;
pthread_t dns_thread_ids[MAX_WORK_THREAD_NUM] ;
pthread_t watch_cmu_thread_id;
uint8_t g_hwdst[ETHER_ADDR_LEN] = {0};
bool
init_processor ()
{
	memset(http_thread_ids,0,sizeof(http_thread_ids));
	memset(dns_thread_ids,0,sizeof(dns_thread_ids));

	g_url_hash_table = NULL;
	g_url_hash_table_reload = NULL;
	g_dns_hash_table = NULL;
	g_dns_hash_table_reload = NULL;
	g_url_extensions_hash_table = NULL;
	g_url_extensions_hash_table_reload = NULL;
	
	return init_iprange();
}

static void
printHelp (void)
{
	printf ("-h              [Print help]\n");
	printf ("-v              [Print version]\n");
	printf ("-x              [set debug mode]\n");
	printf ("-i ethx         [set input device name]\n");
	printf ("-o ethy         [set output device name]\n");
	printf ("-m              [set mac addr eg:E41F134E7B42]\n");

	printf("*********************************************************************************\n");
	printf("Four config files : \n");
	printf("dnsReflector config file : %s \n" , CONFIG_NAME);
	printf("dns list file : %s \n" , DNS_LIST_NAME);
	printf("black ip addr list file : %s \n" , BLACK_SRC_LIST_NAME);
	printf("white ip addr list file : %s \n" , WHITE_SRC_LIST_NAME);
	printf("*********************************************************************************\n");
}

char *get_proc_name(char*dirname)
{
	char *proc_name= strrchr(dirname,'/');
	if(NULL==proc_name) 
		proc_name = dirname;
	else proc_name ++ ;
	return proc_name ;
}

void save_pid( )
{
	pid_t m = getpid( );
	assert(m>0);
	char cmd[128] ;
	snprintf(cmd,sizeof(cmd),"mkdir -p %s",REFLECT_PDIR);
	system(cmd);
	usleep(500);
	memset(cmd,0,sizeof(cmd));
	snprintf(cmd,sizeof(cmd),"echo %d > %s",m,REFLECT_PID);
	system(cmd);
	usleep(500);
}

void delete_pid( )
{
	char cmd[128] ;
	snprintf(cmd,sizeof(cmd),"rm -rf  %s",REFLECT_PID);
	system(cmd);
} 

static int myhex2bin(const char *src, unsigned char *dst)
{
    int idx =0; 
    int len = strlen(src);
    if (len != 12) {
        fprintf(stderr, "Mac %s error.\n", src);
        return -1;
    }
    int i,j;
    for(j=0 ; j <len ;j=j+2,idx ++){
        for(i = j ; i < j+2 ; i++){
            unsigned char c = src[i];
            int k =0; 
            if(c >='a' && c<='f')
                k = c -'a' + 10; 
            else if(c >='A' && c<='F')
                k = c -'A' + 10; 
            else if(c >= '0' && c <= '9')
                k = c -'0';
            if( i == j)
                dst[idx] = k;
            else
                dst[idx] = (dst[idx] <<4) + k;
        }   
    }   
    return idx;
}


int
main(int argc, char *argv[])
{
  	char c;
 	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fcode;
	char *proc_name = get_proc_name(argv[0]);	
	char *conf_path = CONFIG_NAME;
	int ret = 0 ;
    int mac_set_flag = 0;
	
	memset(squid_ip,0,sizeof(squid_ip));
	memset(g_hwdst,0,sizeof(g_hwdst));

	while ((c = getopt (argc, argv, "c:vhxi:o:m:")) != -1)
	{
		switch (c)
		{
			case 'c':
				conf_path = strdup(optarg);
				break;
			case 'o':
				out_device = strdup(optarg);
				break;
			case 'h':
				printHelp();
				return (0);
				break;
			case 'v':
				printf("Version : %s\n",REFLECTORVERSION);
				return 0;
			case 'x':
				isdebug = 1;
				break;
			case 'i':
				device = strdup(optarg);
				break;
            case 'm':
                if (myhex2bin(strdup(optarg), g_hwdst) == -1) {
                    printHelp ();
                    return 0;
                }
                mac_set_flag = 1;
                break;
			default :
				break;
		}
	}	

    if (!mac_set_flag) {
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!\nPlease take the '-m' option as dest mac addr\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

		printHelp();
        return 0;
    }

				
	printf("input device : %s\n", device );
	printf("output device : %s\n", out_device );	
	

	if(0 != strcmp(REFLECTOR_PROC_NAME,proc_name))
	{
		fprintf(stderr,"The process name is not '%s' , quit.\n",REFLECTOR_PROC_NAME);
		exit(1);
	}

/*  For single progress

	pid_t pid = 0;	
	pid = get_pid(REFLECTOR_PROC_NAME);
	if(0 < pid)
	{
		printf("A process named '%s' is running, pid is %d.\n",REFLECTOR_PROC_NAME,pid);
		exit(0);
	}
	
	save_pid( );				
*/

	if(! parse_config(conf_path)) 
	{
		fprintf(stderr,"ParseConfig failed. use default config\n");
		bpfilter = REFLECTOR_BPFILTER;
	}

	
	dns_reflector = true ;
	url_reflector = false;
	if( NULL == device || !strlen(device) )
	{
		fprintf(stderr,"No input device .\n");
		printHelp();
		return 1;
	}
	
	if( NULL == out_device || !strlen(out_device) )
	{
		fprintf(stderr,"No output device .\n");
		printHelp();
		return 1;
	}

	printf ("Capturing from %s\n", device);
	 
	if(!init_processor( )) 
	{
		fprintf(stderr,"Init_processor failed.\n");
		ret = 1;
		goto done;	
	}

	if(!init_dns_hash_table() ) 
	{
		fprintf(stderr,"init_dns_hash_table failed.\n");
		ret = 1 ;
		goto done ;
	}

#define DNSRFL_WLIST_PATH	"/usr/local/dnsReflector/etc/wlist.list"
#define DNSRFL_BLIST_PATH	"/usr/local/dnsReflector/etc/blist.list"

	if(hostlist_init(DNSRFL_WLIST_PATH, DNSRFL_BLIST_PATH)){
		fprintf(stderr, "hostlist_init failed\n");
		ret = 1;
		goto done;
	}

#ifdef HASH_COLLISION_TEST
	collision_info(&g_dns_hash_table);
#endif

	printf("Dns hash talbe created.\n");	

	char err_buf[LIBNET_ERRBUF_SIZE];
    net_t =libnet_init(LIBNET_LINK, out_device, err_buf);
	if(NULL==net_t)
	{
		fprintf(stderr,"libnet_init failed:%s.\n",err_buf);
		exit(1);
	}

	// create n reflactor threads , n = reflactor_thread_count.
	if( !create_reflactor_threads( ) )
	{
		fprintf(stderr, "Can't create reflactor_threads.\n");
		ret = 1 ;
		goto done ;
	}
	printf("Reflector threads created .\n");

	/* hardcode: promisc=1, to_ms=500 */
	int promisc = 1;
	if ((pd = pcap_open_live (device, DEFAULT_SNAPLEN,
					promisc, 5, errbuf)) == NULL)
	{
		fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		ret = 1 ;
		goto done ;
	}

	datalink = pcap_datalink (pd);

	if(bpfilter[0] != '\0'){
		printf("bpfilter %s\n", bpfilter);
		if (pcap_compile (pd, &fcode, bpfilter,  1, 0xFFFFFF00) < 0)
		{
			fprintf(stderr, "pcap_compile error: '%s' \n", pcap_geterr (pd));
			ret = 1 ;
			goto done ;
		}
		else
		{
			if (pcap_setfilter (pd, &fcode) < 0)
			{
				fprintf (stderr, "pcap_setfilter error: '%s' \n", pcap_geterr (pd));
				ret = 1 ;
				goto done ;
			}
		}
	}
		
	if(NULL != pd)	pcap_loop (pd, -1, gotPacket , NULL);
	printf("pcap_loop finished.\n");	
done:

	hostlist_destroy();
	delete_pid( );
	exit(ret);
}

