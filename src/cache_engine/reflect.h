#ifndef _REFLECT_THREADENTRY_H_
#define _REFLECT_THREADENTRY_H_
#include "global.h"
#include "pkt_process.h"
#include "http_sqs.h"

extern pthread_t http_thread_ids[MAX_WORK_THREAD_NUM] ;
extern pthread_t dns_thread_ids[MAX_WORK_THREAD_NUM] ;
extern pthread_t watch_cmu_thread_id;

extern httpsqs *httpsqs_base  ; 
extern dnssqs *dnssqs_base  ; 
extern bool create_reflactor_threads( );

#endif 



