#include <unistd.h>
#include <dirent.h>
#include <sys/types.h> 
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "global.h"

pid_t get_pid(const char* pidName)
{
    pid_t ret = 0 ;
    DIR *dir;	 
    struct dirent *next;   
    dir = opendir("/proc");
	
    if (!dir)
        fprintf(stderr,"Cannot open /proc");
	
    while ((next = readdir(dir)) != NULL) 
	{
        FILE *status;
        char filename[MAX_DIRNAME_LEN];
        char buffer[MAX_LINE_LEN];
        char name[MAX_DIRNAME_LEN];

        /* Must skip ".." since that is outside /proc */
        if (strcmp(next->d_name, "..") == 0)
            continue;

        /* If it isn't a number, we don't want it */
        if (!isdigit(*next->d_name))continue;

        sprintf(filename, "/proc/%s/status", next->d_name);
        if (! (status = fopen(filename, "r")) )
            continue;
 
        if (fgets(buffer, MAX_LINE_LEN-1, status) == NULL) 
		{
            fclose(status);
            continue;
        }
        fclose(status);

        /* Buffer should contain a string like "Name:   binary_name" */
        sscanf(buffer, "%*s %s", name);
        if (strcmp(name, pidName) == 0)
		{
			int temp = strtol(next->d_name, NULL, 0);
			if( getpid() != temp )
			{
				ret = temp ;
				goto exit;
			}
        }
    } 
exit :
    return ret;
}


