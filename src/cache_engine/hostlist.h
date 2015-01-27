#ifndef XFG8_RFL_EEIWANT_HOSTLIST_H
#define XFG8_RFL_EEIWANT_HOSTLIST_H

extern int wlist_used;
extern int blist_used;
extern int max_size;
extern int bucket_size;

int hostlist_init(const char *whitelist_path, const char *blacklist_path);
int hostlist_pass(unsigned char *key, size_t len);
void hostlist_destroy();

#define hostlist_blist_used()	(blist_used == 1)
#define hostlist_wlist_used()	(wlist_used == 1)

#define hostlist_bucket_size()	bucket_size
#define hostlist_max_size()		max_size

#endif
