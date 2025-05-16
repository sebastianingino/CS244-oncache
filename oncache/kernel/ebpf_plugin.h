#ifndef ONCACHE_PLUGIN_H
#define ONCACHE_PLUGIN_H

#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include "common/common.h"

// Egress cache L2: host destination IP -> (outer headers, inner MAC header,
// host interface index)
struct egress_data {
    outer_headers_t outer;
    struct ethhdr inner;
    __u32 ifindex;
};

// Ingress cache: container destination IP -> (inner MAC header, veth interface
// index) vindex maintained by daemon, inner MAC header maintained by eBPF
struct ingress_data {
    struct ethhdr eth;
    __u32 vindex;
};

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
};

#endif  // ONCACHE_PLUGIN_H
