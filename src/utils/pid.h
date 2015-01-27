#ifndef __REFLECT_PID_H__
#define __REFLECT_PID_H__
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h> 
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

extern pid_t get_pid(const char* process_name);

#endif 

