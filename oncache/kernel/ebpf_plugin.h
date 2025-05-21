#ifndef ONCACHE_PLUGIN_H
#define ONCACHE_PLUGIN_H

#include <linux/types.h>
// ^ must come first

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

typedef __be32 addr_t;
typedef __u8 bool_t;
#define true 1
#define false 0

// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
#define VXLAN_HEADER_LEN 8

// Outer header structure: Ethernet + IP + UDP + VXLAN
// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
typedef struct outer_headers_t {
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    __u8 vxlan[VXLAN_HEADER_LEN];
} __attribute__((packed)) outer_headers_t;

// Inner header structure: Ethernet + IP
// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
typedef struct inner_headers_t {
    struct ethhdr eth;
    struct iphdr ip;
} __attribute__((packed)) inner_headers_t;

// Encapsulated header structure: outer + inner
// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
typedef struct encap_headers_t {
    outer_headers_t outer;
    inner_headers_t inner;
} __attribute__((packed)) encap_headers_t;

// Egress cache L2: host destination IP -> (outer headers, inner MAC header,
// host interface index)
struct egress_data {
    outer_headers_t outer;
    struct ethhdr inner;
    __u32 ifindex;
};

// Ingress cache: container destination IP -> (veth interface index, inner MAC
// header)
// vindex maintained by daemon, inner MAC header maintained by eBPF
struct ingress_data {
    __u32 vindex;
    struct ethhdr eth;
} __attribute__((packed));

// Filter cache: (source IP, source port, dest IP, dest port, protocol) ->
// (ingress action, egress action)
struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u8 protocol;
};

// Filter action: ingress and egress allow (1) or deny (0)
struct filter_action {
    __u8 ingress : 1, egress : 1;
};

// Interface map: interface index -> (MAC address, IP address)
struct interface_data {
    __u8 mac[ETH_ALEN];
    addr_t ip;
} __attribute__((packed));

// Check if UDP port is VXLAN
// See https://datatracker.ietf.org/doc/html/rfc7348#section-8
//     https://en.wikipedia.org/wiki/Virtual_Extensible_LAN
static bool_t is_vxlan_port(__u16 port) {
    return port == bpf_htons(4789) || port == bpf_htons(8472);
}

// Check if UDP port is GENEVE
// See https://datatracker.ietf.org/doc/html/rfc8926#section-3.1
static bool_t is_geneve_port(__u16 port) { return port == bpf_htons(6081); }

// Check if packet is a VXLAN packet
// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
static bool_t is_vxlan_pkt(encap_headers_t *headers) {
    return headers->outer.eth.h_proto == bpf_htons(ETH_P_IP) &&
           headers->outer.ip.protocol == IPPROTO_UDP &&
           (is_vxlan_port(headers->outer.udp.dest) ||
            is_geneve_port(headers->outer.udp.dest));
}

// Check if packet was marked as missed
// See https://en.wikipedia.org/wiki/Type_of_service#DSCP_and_ECN
static bool_t has_mark(inner_headers_t *inner, __u8 marker) {
    return inner->ip.tos & marker;
}

// Mark packet as missed
// See https://en.wikipedia.org/wiki/Type_of_service#DSCP_and_ECN
static void mark(inner_headers_t *inner, __u8 marker, bool_t set) {
    if (set) {
        inner->ip.tos |= marker;
    } else {
        inner->ip.tos &= ~marker;
    }
}

// Convert inner headers to flow key
// See https://datatracker.ietf.org/doc/html/rfc791#section-3.1
static bool_t to_flow_key(inner_headers_t *headers, struct __sk_buff *skb,
                          struct flow_key *key) {
    // Check if the inner header is valid
    if (headers->eth.h_proto != bpf_htons(ETH_P_IP)) {
        return false;
    }

    key->src_ip = headers->ip.saddr;
    key->dst_ip = headers->ip.daddr;
    key->protocol = headers->ip.protocol;
    // Check if the packet is long enough
    switch (headers->ip.protocol) {
        case IPPROTO_TCP:
            if (skb->data_end < (__u64)headers + sizeof(inner_headers_t) +
                                    sizeof(struct tcphdr)) {
                return false;
            }
            struct tcphdr *tcp_hdr =
                (struct tcphdr *)((__u8 *)headers + sizeof(inner_headers_t));
            key->src_port = tcp_hdr->source;
            key->dst_port = tcp_hdr->dest;
            break;
        case IPPROTO_UDP:
            if (skb->data_end < (__u64)headers + sizeof(inner_headers_t) +
                                    sizeof(struct udphdr)) {
                return false;
            }
            struct udphdr *udp_hdr =
                (struct udphdr *)((__u8 *)headers + sizeof(inner_headers_t));
            key->src_port = udp_hdr->source;
            key->dst_port = udp_hdr->dest;
            break;
        default:
            return false;
    }

    return true;
}

// Check if two buffers are equal
static inline bool_t equal_buf(volatile __u8 *buf1, volatile __u8 *buf2,
                               __u32 len) {
    for (__u32 i = 0; i < len; i++) {
        if (buf1[i] != buf2[i]) {
            return false;
        }
    }
    return true;
}

#endif  // ONCACHE_PLUGIN_H
