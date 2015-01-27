#ifndef _REFLECT_LOGGER_H_
#define _REFLECT_LOGGER_H_

extern logsqs * logsqs_base ;
extern bool create_log_thread( );
extern char *log_dir ;
extern pthread_t log_thread_id ;

#endif

