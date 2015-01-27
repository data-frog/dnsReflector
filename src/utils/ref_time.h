#ifndef __REF_TIME_H__
#define __REF_TEIM_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#include <time.h>

extern void time_to_str(char *timebuf,const char*format );
extern 	int32_t gmt2local (time_t t); 
extern long delta_time (struct timeval *now, struct timeval *before) ; 

#endif 

