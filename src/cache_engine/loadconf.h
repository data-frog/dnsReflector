#ifndef _REFLECT_LOADCONF_H_
#define _REFLECT_LOADCONF_H_

enum loadConfigResults
{
	FILE_NOT_VALID = 0 ,
	FILE_VALID_AND_NOT_MODIFIED ,
	FILE_VALID_AND_MODIFIED ,
};

extern bool dns_reflector;
extern bool url_reflector;

bool parse_config(const char* conf_path);

extern char *conf_dir ;
extern char conf_crc[33] ;
#endif 

