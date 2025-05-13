#include "ebpf_plugin.h"

#define MAX_ENTRIES 1024

// Egress cache L1: container destination IP -> host destination IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, addr_t);
    __type(value, addr_t);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_host_cache SEC(".maps");

// Egress cache L2: host destination IP -> (outer headers, inner MAC header, host interface index)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, addr_t);
    __type(value, struct egress_headers);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_data_cache SEC(".maps");

// Ingress cache: container destination IP -> (inner MAC header, veth interface index)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, addr_t);
    __type(value, struct ingress_headers);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_cache SEC(".maps");

// Filter cache: (source IP, source port, dest IP, dest port, protocol) -> (ingress action, egress action)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct filter_action);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} filter_cache SEC(".maps");

// Egress hook
SEC("tc_egress")
int tc_egress(struct __sk_buff *skb) {
    bpf_printk("tc_egress called\n");

    return TC_ACT_OK;
}

// Ingress hook


char _license[] SEC("license") = "GPL";
