/*
 *
 *
 *
 *
 */
#ifndef __REFLACETOR_HTTPSQS__
#define __REFLACETOR_HTTPSQS__

#include "global.h" 
#include "packet.h"

#define MIN_HTTPSQS_CAPACITY  2<<9
#define DEFAULT_HTTPSQS_CAPACITY 2<<11
#define TEST_HTTPSQS_CAPACITY 2<<3

typedef struct _pkt_data_node {
	pkt_data    pkt ;
	volatile bool 	  valid   ;
}pkt_data_node;

typedef struct _httpsqs{
	pkt_data_node * base ;
	volatile int head_position  ;
	volatile int rear_position   ;
	int capacity ;
}httpsqs;

typedef httpsqs  dnssqs;
typedef httpsqs  logsqs;

extern bool httpsqs_init(const int capacity, httpsqs *psqs) ;
extern void httpsqs_push_back(const pkt_data *p_pkt,httpsqs *psqs);
extern bool httpsqs_pop_front(pkt_data *out,httpsqs *psqs);
extern void httpsqs_clear(httpsqs *psqs);
extern int httpsqs_capacity(const httpsqs *psqs);
extern int httpsqs_size(const httpsqs *psqs);

#endif 

