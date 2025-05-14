#ifndef ONCACHE_PLUGIN_H
#define ONCACHE_PLUGIN_H

#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include "common/common.h"

struct egress_data {
    outer_headers_t outer;
    struct ethhdr inner;
    __u32 ifindex;
};

struct ingress_data {
    struct ethhdr inner;
    __u32 vindex;
};

struct flow_key {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u8 protocol;
};

struct filter_action {
    __u8 ingress : 1, egress : 1;
};

#endif  // ONCACHE_PLUGIN_H
