#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include "libngx_init.h"

//#include "global.h" comment global.h easy for reuse by other programm

#define CPU_DEFAULT_CACHELINE		64

extern uintptr_t	ngx_cacheline_size;

void
libngx_init(){
	FILE *fp = NULL;
	int cpu_cacheline;

	fp = fopen("/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size", "r");
	if(fp == NULL){
		//xLog_R_master(RUN_WARN, "GET_CPU_CACHELINE_FAIL" "%s", strerror(errno));
		ngx_cacheline_size = CPU_DEFAULT_CACHELINE;
	}else{
		fscanf(fp, "%d", &cpu_cacheline);
		ngx_cacheline_size = cpu_cacheline;
		fclose(fp);
	}
	//xLog_R_master(RUN_INFO, "NGX_CACHELINE_SIZE", "%lu", ngx_cacheline_size);
}

uintptr_t
libngx_get_cacheline(){
	return ngx_cacheline_size;
}
