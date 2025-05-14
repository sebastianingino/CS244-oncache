#include "ebpf_plugin.h"

#define MAX_ENTRIES 1024
// Marker for missed packets (note: first 2 bits are reserved for ECN)
#define MISSED_MARK (1 << 2)
// Marker for established flows (note: first 2 bits are reserved for ECN)
#define EST_MARK (1 << 3)
#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(...) bpf_printk("[DEBUG] " __VA_ARGS__)
#else
#define DEBUG_PRINT(...) \
    {                    \
    }
#endif
#define ERROR_PRINT(...) bpf_printk("[ERROR] " __VA_ARGS__)

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
static inline bool_t is_vxlan_pkt(outer_headers_t *outer) {
    return outer->eth.h_proto == bpf_htons(ETH_P_IP) &&
           outer->ip.protocol == IPPROTO_UDP && is_vxlan_port(outer->udp.dest);
}

// Check if packet was marked as missed
// See https://en.wikipedia.org/wiki/Type_of_service#DSCP_and_ECN
static inline bool_t has_mark(inner_headers_t *inner, __u8 marker) {
    return inner->ip.tos & marker;
}

// Mark packet as missed
// See https://en.wikipedia.org/wiki/Type_of_service#DSCP_and_ECN
static inline void mark(inner_headers_t *inner, __u8 marker, bool_t set) {
    if (set) {
        inner->ip.tos |= marker;
    } else {
        inner->ip.tos &= ~marker;
    }
}

// Convert inner headers to flow key
// See https://datatracker.ietf.org/doc/html/rfc791#section-3.1
static inline struct flow_key to_flow_key(encap_headers_t *inner) {
    struct flow_key key = {
        .src_ip = inner->ip.saddr,
        .dst_ip = inner->ip.daddr,
        .protocol = inner->ip.protocol,
    };
    switch (inner->ip.protocol) {
        case IPPROTO_TCP:
            key.src_port = inner->tcp.source;
            key.dst_port = inner->tcp.dest;
            break;
        case IPPROTO_UDP:
            key.src_port = inner->udp.source;
            key.dst_port = inner->udp.dest;
            break;
        default:
            // Theoretically unreachable
            key.src_port = 0;
            key.dst_port = 0;
            break;
    }

    return key;
}

// Egress init hook
// Attached to outgoing packets, host interface
SEC("egress_init")
int egress_init_prog(struct __sk_buff *skb) {
    DEBUG_PRINT("egress called\n");

    /** BEGIN: Packet Validation */
    // Check if the skb is valid and is long enough
    // Note: we expect encapsulation since we're attached to the host interface
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

    // Check if the inner packet is long enough
    switch (inner->ip.protocol) {
        case IPPROTO_TCP:
            if (skb->len < sizeof(outer_headers_t) + sizeof(inner_headers_t) +
                               sizeof(struct tcphdr)) {
                DEBUG_PRINT("Invalid inner TCP header\n");
                return TC_ACT_OK;
            }
            break;
        case IPPROTO_UDP:
            if (skb->len < sizeof(outer_headers_t) + sizeof(inner_headers_t) +
                               sizeof(struct udphdr)) {
                DEBUG_PRINT("Invalid inner UDP header\n");
                return TC_ACT_OK;
            }
            break;
        default:
            DEBUG_PRINT("Unsupported protocol: %u\n", inner->ip.protocol);
            return TC_ACT_OK;
    }

    // Check if the packet is marked as missed
    if (!has_mark(inner, MISSED_MARK)) {
        DEBUG_PRINT("Packet not marked as missed\n");
        return TC_ACT_OK;
    }

    // Check if the packet is marked as established
    if (!has_mark(inner, EST_MARK)) {
        DEBUG_PRINT("Packet not marked as established\n");
        return TC_ACT_OK;
    }
    /** END: Packet Validation */

    /** BEGIN: Cache Initialization */
    addr_t host_dst_ip = outer->ip.daddr;
    addr_t container_dst_ip = inner->ip.daddr;
    struct egress_data data = {
        .outer = *outer,
        .inner = inner->eth,
        .ifindex = skb->ifindex,
    };

    // Add mapping (container destination IP -> host destination IP) to the
    // egress cache L1
    int err = bpf_map_update_elem(&egress_host_cache, &container_dst_ip,
                                  &host_dst_ip, BPF_NOEXIST);
    if (err) {
        ERROR_PRINT("Failed to update egress_host_cache: %d\n", err);
        return TC_ACT_OK;
    } else {
        DEBUG_PRINT("Updated egress_host_cache: %u -> %u\n", container_dst_ip,
                    host_dst_ip);
    }

    // Add mapping (host destination IP -> (outer headers, inner MAC header,
    // ifindex)) to the egress cache L2
    err = bpf_map_update_elem(&egress_data_cache, &host_dst_ip, &data,
                              BPF_NOEXIST);
    if (err) {
        ERROR_PRINT("Failed to update egress_data_cache: %d\n", err);
        return TC_ACT_OK;
    } else {
        DEBUG_PRINT("Updated egress_data_cache: %u -> egress_data\n",
                    host_dst_ip);
    }

    // Add mapping (source IP, source port, dest IP, dest port, protocol) ->
    // (ingress action, egress action) to the filter cache
    struct flow_key key = to_flow_key((encap_headers_t *)inner);
    struct filter_action action = {
        .ingress = 0,
        .egress = 1,
    };
    err = bpf_map_update_elem(&filter_cache, &key, &action, BPF_NOEXIST);
    if (err) {
        // If the entry already exists, update the egress action
        struct filter_action *existing_action =
            bpf_map_lookup_elem(&filter_cache, &key);
        if (existing_action) {
            existing_action->egress = 1;
            DEBUG_PRINT("Updated filter_cache\n");
        } else {
            ERROR_PRINT("Failed to update filter_cache: %d\n", err);
            return TC_ACT_OK;
        }
    } else {
        DEBUG_PRINT("Updated filter_cache\n");
    }
    /** END: Cache Initialization */

    // Clear packet marks
    mark(inner, MISSED_MARK, 0);
    mark(inner, EST_MARK, 0);

    return TC_ACT_OK;
}

// Egress hook (called before egress_init)
// Attached to outgoing packets, host veth interface
SEC("egress")
int egress_prog(struct __sk_buff *skb) {
    DEBUG_PRINT("egress called\n");

    return TC_ACT_OK;
}

// Ingress init hook
// Attached to incoming packets, container veth interface
SEC("ingress_init")
int ingress_init_prog(struct __sk_buff *skb) {
    DEBUG_PRINT("ingress_init called\n");

    return TC_ACT_OK;
}

// Ingress hook (called before ingress_init)
// Attached to incoming packets, host interface
SEC("ingress")
int ingress_prog(struct __sk_buff *skb) {
    DEBUG_PRINT("ingress called\n");

    /** BEGIN: Packet Validation */
    // Check if the skb is valid and is long enough
    // Note: NO encapsulation since we're attached to the container veth
    if (!skb || skb->len < sizeof(inner_headers_t)) {
        DEBUG_PRINT("Invalid skb\n");
        return TC_ACT_OK;
    }

    // Get the headers
    inner_headers_t *inner = (inner_headers_t *)(skb->data);

    // Check if the inner header is valid
    if (inner->eth.h_proto != bpf_htons(ETH_P_IP)) {
        DEBUG_PRINT("Invalid inner header\n");
        return TC_ACT_OK;
    }

    // Check if the packet is marked as missed
    if (!has_mark(inner, MISSED_MARK)) {
        DEBUG_PRINT("Packet not marked as missed\n");
        return TC_ACT_OK;
    }
    // Check if the packet is marked as established
    if (!has_mark(inner, EST_MARK)) {
        DEBUG_PRINT("Packet not marked as established\n");
        return TC_ACT_OK;
    }
    /** END: Packet Validation */

    /** BEGIN: Check Daemon State */
    // Note: container destination IP -> veth index is maintained by the daemon
    // and must exist ahead of time
    struct ingress_data *data =
        bpf_map_lookup_elem(&ingress_cache, &inner->ip.daddr);
    if (!data) {
        DEBUG_PRINT("Ingress data not found for IP: %u\n", inner->ip.daddr);
        return TC_ACT_OK;
    }
    /** END: Check Daemon State */

    /** BEGIN: Cache Initialization */
    // Update the ingress cache with the inner MAC header
    // Note: the veth index is maintained by the daemon
    data->inner = inner->eth;

    // Add mapping (source IP, source port, dest IP, dest port, protocol) ->
    // (ingress action, egress action) to the filter cache
    struct flow_key key = to_flow_key((encap_headers_t *)inner);
    struct filter_action action = {
        .ingress = 1,
        .egress = 0,
    };
    int err = bpf_map_update_elem(&filter_cache, &key, &action, BPF_NOEXIST);
    if (err) {
        // If the entry already exists, update the ingress action
        struct filter_action *existing_action =
            bpf_map_lookup_elem(&filter_cache, &key);
        if (existing_action) {
            existing_action->ingress = 1;
            DEBUG_PRINT("Updated filter_cache\n");
        } else {
            ERROR_PRINT("Failed to update filter_cache: %d\n", err);
            return TC_ACT_OK;
        }
    } else {
        DEBUG_PRINT("Updated filter_cache\n");
    }
    /** END: Cache Initialization */

    // Clear packet marks
    mark(inner, MISSED_MARK, 0);
    mark(inner, EST_MARK, 0);

    return TC_ACT_OK;
}

// License
// See https://eunomia.dev/en/tutorials/20-tc/
char __license[] SEC("license") = "GPL";
