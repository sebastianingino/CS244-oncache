#ifndef ONCACHE_COMMON_H
#define ONCACHE_COMMON_H
#include <linux/types.h>

typedef __u32 addr_t;

typedef struct outer_headers_t {
    __u8 mac[14];
    __u8 ip[20];
    __u8 udp[8];
    __u8 vxlan[8];
} outer_headers_t;

typedef struct inner_headers_t {
    __u8 mac[14];
} inner_headers_t;

#endif  // ONCACHE_COMMON_H
