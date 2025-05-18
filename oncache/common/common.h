#ifndef ONCACHE_COMMON_H
#define ONCACHE_COMMON_H
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

typedef __u32 addr_t;
typedef __u8 bool_t;
#define true 1
#define false 0

// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
#define VXLAN_HEADER_LEN 8

// Outer header structure: Ethernet + IP + UDP + VXLAN
// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
#pragma pack(push, 1)
typedef struct outer_headers_t {
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    __u8 vxlan[VXLAN_HEADER_LEN];
} outer_headers_t;
#pragma pack(pop)

// Inner header structure: Ethernet + IP
// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
#pragma pack(push, 1)
typedef struct inner_headers_t {
    struct ethhdr eth;
    struct iphdr ip;
} inner_headers_t;
#pragma pack(pop)

// Encapsulated header structure: outer + inner
// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
#pragma pack(push, 1)
typedef struct encap_headers_t {
    outer_headers_t outer;
    inner_headers_t inner;
} encap_headers_t;
#pragma pack(pop)

// Check if two buffers are equal
static inline bool_t equal_buf(__u8 *buf1, __u8 *buf2, __u32 len) {
    for (__u32 i = 0; i < len; i++) {
        if (buf1[i] != buf2[i]) {
            return false;
        }
    }
    return true;
}

#endif  // ONCACHE_COMMON_H
