#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "global.h"
#include "http_sqs.h"

#define GET_NEXT_POSITION(position,capacity)  (((position)+1)>=(capacity))?0:((position)+1)

bool httpsqs_init(const int size, httpsqs* psqs)
{
 	int i = 0 ;
 	psqs->capacity = size ; 
	if (psqs->capacity < MIN_HTTPSQS_CAPACITY) psqs->capacity = MIN_HTTPSQS_CAPACITY ;
	psqs->head_position = 0;
    psqs->rear_position = 0 ;

	printf("init %p,head:%d,rear:%d,capacity:%d\n",psqs,psqs->head_position,psqs->rear_position,psqs->capacity);
	psqs->base = (pkt_data_node *)malloc(psqs->capacity*sizeof(pkt_data_node)) ;
	if(NULL == psqs->base)
	{
		fprintf(stderr,"Can't allocate memory httpsqs_init().\n"); 
		return false ;
	}
	for(;i<psqs->capacity;i++) 
	{
		psqs->base[i].valid = false ;
	}
	printf("httpsqs_init ok.\n");
	return true ;
}

void httpsqs_push_back(const pkt_data *p_pkt,httpsqs *psqs)
{
  	int i = 0 ;
	//printf("push %d,head:%d,rear:%d,capacity:%d\n",(int)(psqs),psqs->head_position,psqs->rear_position,psqs->capacity);
	
	if ( GET_NEXT_POSITION(psqs->rear_position,psqs->capacity) == psqs->head_position )
	{
		// printf(" push back - cicle , rear : %d\n",psqs->rear_position);
		// overlap the head with new pkt , clear the other nodes 
		for(i=0;i<psqs->capacity;i++)
			psqs->base[i].valid = false ;
		memcpy((unsigned char*)&psqs->base[psqs->head_position].pkt,(unsigned char*)p_pkt,sizeof(pkt_data));
		psqs->base[psqs->head_position].valid = true ;
		// adjust the rear_position 
		psqs->rear_position = GET_NEXT_POSITION(psqs->head_position,psqs->capacity) ;
	}
	else 
	{
		memcpy((unsigned char*)&psqs->base[psqs->rear_position].pkt,(unsigned char*)p_pkt,sizeof(pkt_data));
		psqs->base[psqs->rear_position].valid = true ;
		psqs->rear_position = GET_NEXT_POSITION(psqs->rear_position,psqs->capacity);
	}
	return ;
}

bool httpsqs_pop_front(pkt_data *out,httpsqs *psqs)
{
	assert(NULL!=out&&NULL!=psqs);
	if(!psqs->base[psqs->head_position].valid )
		return false ;
	memcpy(out,psqs->base+psqs->head_position,sizeof(pkt_data));
	psqs->base[psqs->head_position].valid = false ;
	psqs->head_position = GET_NEXT_POSITION(psqs->head_position,psqs->capacity);	
	return true ;
}

void httpsqs_clear(httpsqs *psqs)
{
	if(NULL!=psqs->base) free(psqs->base) ;
	psqs->base = NULL ;
}

int httpsqs_capacity(const httpsqs *psqs)
{
	return psqs->capacity ;
}
int httpsqs_size(const httpsqs *psqs)
{
	if ( psqs->rear_position > psqs->head_position ) 
		return psqs->rear_position - psqs->head_position ;
	else 
	{
		return (psqs->capacity - psqs->head_position) +( psqs->rear_position + 1) ;
	}
}

