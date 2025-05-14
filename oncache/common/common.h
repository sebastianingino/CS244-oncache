#ifndef ONCACHE_COMMON_H
#define ONCACHE_COMMON_H
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/tcp.h>

typedef __u32 addr_t;
typedef __u8 bool_t;

// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
#define VXLAN_HEADER_LEN 8

// Outer header structure: Ethernet + IP + UDP + VXLAN
// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
typedef struct outer_headers_t {
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    __u8 vxlan[VXLAN_HEADER_LEN];
} outer_headers_t;

// Inner header structure: Ethernet + IP
// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
typedef struct inner_headers_t {
    struct ethhdr eth;
    struct iphdr ip;
} inner_headers_t;

// Inner header structure (superset): Ethernet + IP + TCP/UDP
typedef struct encap_headers_t {
    struct ethhdr eth;
    struct iphdr ip;
    union {
        struct udphdr udp;
        struct tcphdr tcp;
    };
} encap_headers_t;

#endif  // ONCACHE_COMMON_H
