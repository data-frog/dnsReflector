#ifndef XFENGUANG8_LIBNGX_INIT_H
#define XFENGUANG8_LIBNGX_INIT_H

#include <stdint.h>
/*
 * init some global variable need by libngx
 *
 */

void
libngx_init();

uintptr_t
libngx_get_cacheline();

#endif
