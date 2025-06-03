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

#ifdef DEBUG
#define DEBUG_PRINT(...) bpf_printk("[DEBUG] " __VA_ARGS__)
#else
#define DEBUG_PRINT(...) \
    {                    \
    }
#endif
#define INFO_PRINT(...) bpf_printk("[INFO] " __VA_ARGS__)
#define ERROR_PRINT(...) bpf_printk("[ERROR] " __VA_ARGS__)

typedef __be32 addr_t;
typedef __u8 bool_t;
#define true 1
#define false 0

// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
// Note: it's probably ok for GENEVE assuming no variable-length options
// See https://datatracker.ietf.org/doc/html/rfc8926#section-3.1
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
} __attribute__((packed));

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

// Check if packet is a VXLAN or GENEVE packet
// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
//     https://datatracker.ietf.org/doc/html/rfc8926#section-3.1
static bool_t is_encap_pkt(encap_headers_t *headers) {
    if (headers->outer.eth.h_proto != bpf_htons(ETH_P_IP)) {
        DEBUG_PRINT("(is_encap_pkt) Not an IP packet {eth_proto: %d}",
                    headers->outer.eth.h_proto);
        return false;
    }
    if (headers->outer.ip.protocol != IPPROTO_UDP) {
        DEBUG_PRINT("(is_encap_pkt) Not a UDP packet {ip_proto: %d}",
                    headers->outer.ip.protocol);
        return false;
    }
    if (!is_vxlan_port(headers->outer.udp.dest) &&
        !is_geneve_port(headers->outer.udp.dest)) {
        DEBUG_PRINT("(is_encap_pkt) Not a VXLAN or GENEVE packet {port: %d}",
                    bpf_ntohs(headers->outer.udp.dest));
        return false;
    }
    return true;
}

// Check if packet was marked as missed
// See https://en.wikipedia.org/wiki/Type_of_service#DSCP_and_ECN
static bool_t __attribute__((always_inline)) has_mark(inner_headers_t *inner,
                                                      __u8 marker) {
    DEBUG_PRINT("(has_mark) inner->ip.tos: %u", inner->ip.tos);
    return inner->ip.tos & marker;
}

// Mark packet as missed
// See https://en.wikipedia.org/wiki/Type_of_service#DSCP_and_ECN
static void mark(struct __sk_buff *skb, __u32 inner_offset, __u8 marker,
                 bool_t set) {
    __u32 eth_offset = inner_offset + sizeof(struct ethhdr);
    __u32 tos_offset = eth_offset + offsetof(struct iphdr, tos);

    __u8 old_tos;
    if (bpf_skb_load_bytes(skb, tos_offset, &old_tos, sizeof(__u8)) < 0) {
        ERROR_PRINT("(mark) Failed to load old TOS");
        return;
    }
    __u8 new_tos = set ? old_tos | marker : old_tos & ~marker;
    if (bpf_skb_store_bytes(skb, tos_offset, &new_tos, sizeof(__u8), 0) < 0) {
        ERROR_PRINT("(mark) Failed to store new TOS");
        return;
    }

    DEBUG_PRINT("(mark) Marked packet {old: %u, new: %u}", old_tos, new_tos);

    // Update the IP checksum
    bpf_l3_csum_replace(
        skb, eth_offset + offsetof(struct iphdr, check), bpf_htons(old_tos),
        bpf_htons(new_tos),
        2);  // Note: 2 bytes because that's the minimum size See:
             // https://docs.ebpf.io/linux/helper-function/bpf_l3_csum_replace/

    // Mark hash as invalid
    // See: https://docs.ebpf.io/linux/helper-function/bpf_set_hash_invalid/
    bpf_set_hash_invalid(skb);
}

// Convert inner headers to flow key
// See https://datatracker.ietf.org/doc/html/rfc791#section-3.1
static bool_t to_flow_key(inner_headers_t *headers, struct __sk_buff *skb,
                          struct flow_key *key, bool_t egress) {
    // Check if the inner header is valid
    if (headers->eth.h_proto != bpf_htons(ETH_P_IP)) {
        DEBUG_PRINT("(to_flow_key) Not an IP packet {eth_proto: %d}",
                    headers->eth.h_proto);
        return false;
    }

    #ifndef FILTER
    return true;  // No filtering, just return true
    #endif

    key->src_ip = egress ? headers->ip.saddr : headers->ip.daddr;
    key->dst_ip = egress ? headers->ip.daddr : headers->ip.saddr;
    key->protocol = headers->ip.protocol;
    // Check if the packet is long enough
    switch (headers->ip.protocol) {
        case IPPROTO_TCP:
            if (skb->data_end < (__u64)headers + sizeof(inner_headers_t) +
                                    sizeof(struct tcphdr)) {
                DEBUG_PRINT("(to_flow_key) Too short for TCP packet");
                return false;
            }
            struct tcphdr *tcp_hdr =
                (struct tcphdr *)((__u8 *)headers + sizeof(inner_headers_t));
            key->src_port = egress ? tcp_hdr->source : tcp_hdr->dest;
            key->dst_port = egress ? tcp_hdr->dest : tcp_hdr->source;
            break;
        case IPPROTO_UDP:
            if (skb->data_end < (__u64)headers + sizeof(inner_headers_t) +
                                    sizeof(struct udphdr)) {
                DEBUG_PRINT("(to_flow_key) Too short for UDP packet");
                return false;
            }
            struct udphdr *udp_hdr =
                (struct udphdr *)((__u8 *)headers + sizeof(inner_headers_t));
            key->src_port = egress ? udp_hdr->source : udp_hdr->dest;
            key->dst_port = egress ? udp_hdr->dest : udp_hdr->source;
            break;
        default:
            DEBUG_PRINT("(to_flow_key) Not a TCP or UDP packet {ip_proto: %d}",
                        headers->ip.protocol);
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
