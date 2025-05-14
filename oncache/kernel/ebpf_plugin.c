#include "ebpf_plugin.h"

#define MAX_ENTRIES 1024
// Marker for missed packets (note: first 2 bits are reserved for ECN)
#define MISSED_MARK (1 << 2)
// Marker for established flows (note: first 2 bits are reserved for ECN)
#define EST_MARK (1 << 3) 
#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(x) bpf_printk(x)
#else
#define DEBUG_PRINT(x) {}
#endif

// Egress cache L1: container destination IP -> host destination IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, addr_t);
    __type(value, addr_t);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_host_cache SEC(".maps");

// Egress cache L2: host destination IP -> (outer headers, inner MAC header,
// host interface index)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, addr_t);
    __type(value, struct egress_data);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_data_cache SEC(".maps");

// Ingress cache: container destination IP -> (inner MAC header, veth interface
// index)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, addr_t);
    __type(value, struct ingress_data);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_cache SEC(".maps");

// Filter cache: (source IP, source port, dest IP, dest port, protocol) ->
// (ingress action, egress action)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct filter_action);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} filter_cache SEC(".maps");

// Check if UDP port is VXLAN
// See https://datatracker.ietf.org/doc/html/rfc7348#section-8
//     https://en.wikipedia.org/wiki/Virtual_Extensible_LAN
static inline bool_t is_vxlan_port(__u16 port) {
    return port == bpf_htons(4789) || port == bpf_htons(8472);
}

// Check if packet is a VXLAN packet
// See https://datatracker.ietf.org/doc/html/rfc7348#section-5
static inline bool_t is_vxlan_pkt(struct outer_headers_t *outer) {
    return outer->eth.h_proto == bpf_htons(ETH_P_IP) &&
           outer->ip.protocol == IPPROTO_UDP && is_vxlan_port(outer->udp.dest);
}

// Check if packet was marked as missed
// See https://en.wikipedia.org/wiki/Type_of_service#DSCP_and_ECN
static inline bool_t has_mark(struct inner_headers_t *inner, __u8 marker) {
    return inner->ip.tos & marker;
}

// Mark packet as missed
// See https://en.wikipedia.org/wiki/Type_of_service#DSCP_and_ECN
static inline void mark(struct inner_headers_t *inner, __u8 marker) {
    inner->ip.tos |= marker;
}

// Egress init hook
// Attached to outgoing packets, host interface
SEC("egress_init")
int egress_init_prog(struct __sk_buff *skb) {
    DEBUG_PRINT("egress called\n");

    /** BEGIN: Packet Validation */

    // Check if the skb is valid and is long enough
    if (!skb || skb->len < sizeof(outer_headers_t) + sizeof(inner_headers_t)) {
        DEBUG_PRINT("Invalid skb\n");
        return TC_ACT_OK;
    }

    // Get the headers
    outer_headers_t *outer = (outer_headers_t *)(skb->data);
    inner_headers_t *inner =
        (inner_headers_t *)(skb->data + sizeof(outer_headers_t));

    // Check if the outer packet is a VXLAN packet
    if (!is_vxlan_pkt(outer)) {
        DEBUG_PRINT("Not a VXLAN packet\n");
        return TC_ACT_OK;
    }

    // Check if the inner header is valid
    if (inner->eth.h_proto != bpf_htons(ETH_P_IP)) {
        DEBUG_PRINT("Invalid inner header\n");
        return TC_ACT_OK;
    }

    // Check if the packet was not marked as missed
    if (!has_mark(inner, MISSED_MARK)) {
        DEBUG_PRINT("Packet not marked as missed\n");
        return TC_ACT_OK;
    }

    // Check if the packet is not marked as established
    if (!has_mark(inner, EST_MARK)) {
        DEBUG_PRINT("Packet not marked as established\n");
        return TC_ACT_OK;
    }

    /** END: Packet Validation */

    /** BEGIN: Cache Initialization */

    return TC_ACT_OK;
}

// Egress hook (called before egress_init)
// Attached to outgoing packets, host veth interface
SEC("egress")
int egress_prog(struct __sk_buff *skb) {
    bpf_printk("egress called\n");

    return TC_ACT_OK;
}

// Ingress init hook
// Attached to incoming packets, container veth interface
SEC("ingress_init")
int ingress_init_prog(struct __sk_buff *skb) {
    bpf_printk("ingress_init called\n");

    return TC_ACT_OK;
}

// Ingress hook (called before ingress_init)
// Attached to incoming packets, host interface
SEC("ingress")
int ingress_prog(struct __sk_buff *skb) {
    bpf_printk("ingress called\n");

    return TC_ACT_OK;
}

// License
// See https://eunomia.dev/en/tutorials/20-tc/
char __license[] SEC("license") = "GPL";
