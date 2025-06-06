// Enable debug prints
// #define DEBUG

#include "ebpf_plugin.h"

// Maximum number of entries in the caches
#define MAX_ENTRIES 4096

// Marker for missed packets (note: first 2 bits are reserved for ECN)
#define MISSED_MARK (1 << 2)
// Marker for established flows (note: first 2 bits are reserved for ECN)
#define EST_MARK (1 << 3)

// Minimum recommended UDP port for VXLAN
// See: https://datatracker.ietf.org/doc/html/rfc7348#section-5
// Note: we use the same range for GENEVE even though it allows the entire range
// of UDP ports
// See: https://datatracker.ietf.org/doc/html/rfc8926#section-3.3
#define VXLAN_UDP_PORT 49152
// Maximum recommended UDP port for VXLAN
// See: https://datatracker.ietf.org/doc/html/rfc7348#section-5
#define VXLAN_UDP_PORT_MAX 65535

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

// Ingress cache: container destination IP -> (veth interface index, inner MAC
// header)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
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

// Host interface: (MAC address, IP address)
// See: https://ebpf-go.dev/concepts/global-variables/#global-variables
volatile struct interface_data host_interface = {
    .mac = {0},
    .ip = 0,
};

// Egress init hook
// Attached to outgoing packets, host interface
SEC("tc/egress_init")
int egress_init(struct __sk_buff *skb) {
    DEBUG_PRINT("egress_init called");

    /** BEGIN: Packet Validation */
    // Check if the skb is long enough
    // Note: we expect encapsulation since we're attached to the host interface
    // Additional note: we have to check skb->data_end and skb->data without
    // subtraction due to the verifier not liking it otherwise.
    // Additional note: we don't need to check for a NULL pointer since the
    // we're guaranteed that skb->data is not NULL.
    if (skb->data_end < skb->data + sizeof(encap_headers_t)) {
        DEBUG_PRINT("(egress_init) skb is not large enough");
        return TC_ACT_OK;
    }

    // Get the headers
    encap_headers_t *headers = (encap_headers_t *)(skb->data);

    // Check if the outer packet is a VXLAN or GENEVE packet
    if (!is_encap_pkt(headers)) {
        DEBUG_PRINT("(egress_init) Not a VXLAN or GENEVE packet");
        return TC_ACT_OK;
    }

    // Get flow key and check if inner packet is long enough
    struct flow_key key;
    if (!to_flow_key(&headers->inner, skb, &key, true)) {
        DEBUG_PRINT("(egress_init) Failed to create flow key: %d",
                    headers->inner.ip.protocol);
        return TC_ACT_OK;
    }

    // Check if the packet is marked as missed
    if (!has_mark(&headers->inner, MISSED_MARK)) {
        DEBUG_PRINT("(egress_init) Packet to %u not marked as missed: %u",
                    headers->inner.ip.daddr, headers->inner.ip.tos);
        return TC_ACT_OK;
    }

    // Check if the packet is marked as established
    if (!has_mark(&headers->inner, EST_MARK)) {
        DEBUG_PRINT("(egress_init) Packet to %u not marked as established: %u",
                    headers->inner.ip.daddr, headers->inner.ip.tos);
        return TC_ACT_OK;
    }
    /** END: Packet Validation */

    /** BEGIN: Cache Initialization */
    addr_t host_dst_ip = headers->outer.ip.daddr;
    addr_t container_dst_ip = headers->inner.ip.daddr;
    struct egress_data data = {
        .outer = headers->outer,
        .inner = headers->inner.eth,
        .ifindex = skb->ifindex,
    };

    // Add mapping (source IP, source port, dest IP, dest port, protocol) ->
    // (ingress action, egress action) to the filter cache
    // Note: this must be done first since future actions can only be done once
    struct filter_action action = {
        .ingress = 0,
        .egress = 1,
    };
    int err = bpf_map_update_elem(&filter_cache, &key, &action, BPF_NOEXIST);
    if (err) {
        // If the entry already exists, update the egress action
        struct filter_action *existing_action =
            bpf_map_lookup_elem(&filter_cache, &key);
        if (existing_action) {
            existing_action->egress = 1;
            DEBUG_PRINT("(egress_init) Updated filter_cache");
        } else {
            ERROR_PRINT("(egress_init) Failed to update filter_cache: %d", err);
            return TC_ACT_OK;
        }
    } else {
        DEBUG_PRINT("(egress_init) Updated filter_cache");
    }

    // Add mapping (container destination IP -> host destination IP) to the
    // egress cache L1
    err = bpf_map_update_elem(&egress_host_cache, &container_dst_ip,
                              &host_dst_ip, BPF_ANY);
    if (err) {
        ERROR_PRINT("(egress_init) Failed to update egress_host_cache: %d",
                    err);
        return TC_ACT_OK;
    } else {
        DEBUG_PRINT("(egress_init) Updated egress_host_cache: %u -> %u",
                   container_dst_ip, host_dst_ip);
    }

    // Add mapping (host destination IP -> (outer headers, inner MAC header,
    // ifindex)) to the egress cache L2
    err = bpf_map_update_elem(&egress_data_cache, &host_dst_ip, &data, BPF_ANY);
    if (err) {
        ERROR_PRINT("(egress_init) Failed to update egress_data_cache: %d",
                    err);
        return TC_ACT_OK;
    } else {
        DEBUG_PRINT("(egress_init) Updated egress_data_cache: %u -> egress_data",
                   host_dst_ip);
    }
    /** END: Cache Initialization */

    // Clear packet marks
    mark(skb, sizeof(outer_headers_t), MISSED_MARK, 0);
    mark(skb, sizeof(outer_headers_t), EST_MARK, 0);

    return TC_ACT_OK;
}

// Egress hook (called before egress_init)
// Attached to outgoing packets, host veth interface
SEC("tc/egress")
int egress(struct __sk_buff *skb) {
    DEBUG_PRINT("egress called");

    /** BEGIN: Packet Validation */
    // Check if the skb is long enough
    // Note: NO encapsulation since we're attached to the host veth
    if (skb->data_end < skb->data + sizeof(inner_headers_t)) {
        DEBUG_PRINT("(egress) skb is not large enough");
        return TC_ACT_OK;
    }
    // Get the headers
    inner_headers_t *headers = (inner_headers_t *)(skb->data);

    // Get flow key and check if the packet is long enough
    struct flow_key key;
    if (!to_flow_key(headers, skb, &key, true)) {
        DEBUG_PRINT("(egress) Failed to create flow key: %d",
                    headers->ip.protocol);
        return TC_ACT_OK;
    }

    // Get the packet hash for later
    __u32 hash = bpf_get_hash_recalc(skb);

    /** END: Packet Validation */

    /** BEGIN: Step 1: Cache Retrieving */
    /** BEGIN: Forward Cache Validation */
    // Check if mapping in egress cache L1 exists
    addr_t *host_dst_ip =
        bpf_map_lookup_elem(&egress_host_cache, &headers->ip.daddr);
    if (!host_dst_ip) {
        DEBUG_PRINT(
            "(egress) Host destination IP %u not found in egress_host_cache",
            headers->ip.daddr);
        mark(skb, 0, MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    // Check if mapping in egress cache L2 exists
    struct egress_data *data =
        bpf_map_lookup_elem(&egress_data_cache, host_dst_ip);
    if (!data) {
        DEBUG_PRINT("(egress) Egress data not found for host destination IP: %u",
                   *host_dst_ip);
        mark(skb, 0, MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    
    // Check if the packet is allowed in the filter cache
    struct filter_action *action = bpf_map_lookup_elem(&filter_cache, &key);
    if (!action) {
        DEBUG_PRINT("(egress) Filter action not found for flow key");
        mark(skb, 0, MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    if (!action->egress || !action->ingress) {
        DEBUG_PRINT("(egress) Filter action not allowed: ingress=%u, egress=%u",
                   action->ingress, action->egress);
        mark(skb, 0, MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    /** END: Forward Cache Validation */

    /** BEGIN: Reverse Cache Validation */
    struct ingress_data *ingress_data =
        bpf_map_lookup_elem(&ingress_cache, &headers->ip.saddr);
    if (!ingress_data) {
        INFO_PRINT("(egress) Ingress data not found for IP: %u",
                   headers->ip.saddr);
        mark(skb, 0, MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    /** END: Reverse Cache Validation */
    /** END: Step 1: Cache Retrieving */

    /** BEGIN: Step 2: Encapsulation and Intra-host Routing */
    // Expand the socket buffer to the size of the outer headers
    // See: https://docs.ebpf.io/linux/helper-function/bpf_skb_adjust_room/
    int err = bpf_skb_adjust_room(
        skb, sizeof(outer_headers_t),
        BPF_ADJ_ROOM_MAC,  // expansion at the MAC (between L2 and L3) layer
        BPF_F_ADJ_ROOM_FIXED_GSO |          // Do not change GSO size because of
                                            // encapsulation
            BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |  // Reserve space for tunnel header
            BPF_F_ADJ_ROOM_ENCAP_L4_UDP |   // L3 tunnel type: UDP
            BPF_F_ADJ_ROOM_ENCAP_L2(
                sizeof(struct ethhdr)) |   // Reserve space for outer MAC header
            BPF_F_ADJ_ROOM_ENCAP_L2_ETH);  // L2 tunnel type: Ethernet
    if (err || skb->data_end < skb->data + sizeof(encap_headers_t)) {
        ERROR_PRINT("(egress) Failed to adjust skb room: %d", err);
        return TC_ACT_OK;
    }

    // Set the outer headers
    encap_headers_t *encap_headers = (encap_headers_t *)(skb->data);
    encap_headers->outer = data->outer;
    encap_headers->inner.eth = data->inner;
    // Update the UDP length
    encap_headers->outer.udp.len =
        bpf_htons(skb->len - sizeof(struct ethhdr) - sizeof(struct iphdr));
    // Update the UDP source port
    __be16 src_port = bpf_htons(VXLAN_UDP_PORT +
                                (hash % (VXLAN_UDP_PORT_MAX - VXLAN_UDP_PORT)));
    encap_headers->outer.udp.source = src_port;
    // Update the IP length and checksum
    __u16 old_len = encap_headers->outer.ip.tot_len;
    __u16 new_len = bpf_htons(skb->len - sizeof(struct ethhdr));
    encap_headers->outer.ip.tot_len = new_len;
    // L3 checksum replacement is incremental
    // See: https://docs.ebpf.io/linux/helper-function/bpf_l3_csum_replace/
    // Note: this makes me sad
    bpf_l3_csum_replace(skb,
                        sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                        old_len, new_len, sizeof(__u16));

    return bpf_redirect(data->ifindex, 0);
}

// Ingress init hook
// Attached to incoming packets, container veth interface
SEC("tc/ingress_init")
int ingress_init(struct __sk_buff *skb) {
    DEBUG_PRINT("ingress_init called");

    /** BEGIN: Packet Validation */
    // Check if the skb is valid and is long enough
    // Note: NO encapsulation since we're attached to the container veth
    if (skb->data_end < skb->data + sizeof(inner_headers_t)) {
        DEBUG_PRINT("(ingress_init) skb is not large enough");
        return TC_ACT_OK;
    }

    // Get the headers
    inner_headers_t *headers = (inner_headers_t *)(skb->data);

    // Get flow key and check if the packet is long enough
    struct flow_key key;
    if (!to_flow_key(headers, skb, &key, false)) {
        DEBUG_PRINT("(ingress_init) Failed to create flow key: %d",
                    headers->ip.protocol);
        return TC_ACT_OK;
    }

    // Check if the packet is marked as missed
    if (!has_mark(headers, MISSED_MARK)) {
        DEBUG_PRINT("(ingress_init) Packet from %u not marked as missed: %u",
                    headers->ip.saddr, headers->ip.tos);
        return TC_ACT_OK;
    }
    // Check if the packet is marked as established
    if (!has_mark(headers, EST_MARK)) {
        DEBUG_PRINT(
            "(ingress_init) Packet from %u not marked as established: %u",
            headers->ip.saddr, headers->ip.tos);
        return TC_ACT_OK;
    }
    /** END: Packet Validation */

    /** BEGIN: Check Daemon State */
    // Note: container destination IP -> veth index is maintained by the daemon
    // and must exist ahead of time
    struct ingress_data *data =
        bpf_map_lookup_elem(&ingress_cache, &headers->ip.daddr);
    if (!data) {
        INFO_PRINT("(ingress_init) Ingress data not found for IP: %u",
                   headers->ip.daddr);
        return TC_ACT_OK;
    }
    /** END: Check Daemon State */

    /** BEGIN: Cache Initialization */
    // Update the ingress cache with the inner MAC header
    // Note: the veth index is maintained by the daemon
    data->eth = headers->eth;

    // Add mapping (source IP, source port, dest IP, dest port, protocol) ->
    // (ingress action, egress action) to the filter cache
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
            DEBUG_PRINT("(ingress_init) Updated filter_cache");
        } else {
            ERROR_PRINT("(ingress_init) Failed to update filter_cache: %d",
                        err);
            return TC_ACT_OK;
        }
    } else {
        DEBUG_PRINT("(ingress_init) Updated filter_cache");
    }
    /** END: Cache Initialization */

    // Clear packet marks
    mark(skb, 0, MISSED_MARK, 0);
    mark(skb, 0, EST_MARK, 0);

    return TC_ACT_OK;
}

// Ingress hook (called before ingress_init)
// Attached to incoming packets, host interface
SEC("tc/ingress")
int ingress(struct __sk_buff *skb) {
    DEBUG_PRINT("(ingress) ingress called");

    /** BEGIN: Packet Validation */
    // Check if the skb is valid and is long enough
    // Note: we expect encapsulation since we're attached to the host interface
    if (skb->data_end < skb->data + sizeof(encap_headers_t)) {
        DEBUG_PRINT("(ingress) skb is not large enough");
        return TC_ACT_OK;
    }

    // Get the headers
    encap_headers_t *headers = (encap_headers_t *)(skb->data);

    // Check if the outer packet is a VXLAN or GENEVE packet
    if (!is_encap_pkt(headers)) {
        DEBUG_PRINT("(ingress) Not a VXLAN or GENEVE packet");
        return TC_ACT_OK;
    }

    // Get flow key and check if the inner packet is long enough
    struct flow_key key;
    if (!to_flow_key(&headers->inner, skb, &key, false)) {
        DEBUG_PRINT("(ingress) Failed to create flow key: %d",
                    headers->inner.ip.protocol);
        return TC_ACT_OK;
    }

    /** BEGIN: Step 1: Destination Check */
    /** BEGIN: Interface Validation */
    // Get the interface data
    if (host_interface.ip == 0) {
        DEBUG_PRINT("(ingress) Host interface not initialized");
        return TC_ACT_OK;
    }
    // Check if the packet matches the interface data
    if (!equal_buf(host_interface.mac, headers->outer.eth.h_dest, ETH_ALEN)) {
        INFO_PRINT("(ingress) Packet does not match interface eth address");
        return TC_ACT_OK;
    }
    if (host_interface.ip != headers->outer.ip.daddr) {
        INFO_PRINT(
            "(ingress) Packet IP (%u) does not match interface IP address (%u)",
            headers->outer.ip.daddr, host_interface.ip);
        return TC_ACT_OK;
    }
    /** END: Interface Validation */
    /** END: Step 1: Destination Check */

    /** BEGIN: Step 2: Cache Retrieving */
    /** BEGIN: Forward Cache Validation */
    // Check if mapping in ingress cache exists
    struct ingress_data *data =
        bpf_map_lookup_elem(&ingress_cache, &headers->inner.ip.daddr);
    if (!data) {
        INFO_PRINT("(ingress) Ingress data not found for IP: %u",
                   headers->inner.ip.daddr);
        mark(skb, sizeof(outer_headers_t), MISSED_MARK, 1);
        return TC_ACT_OK;
    }

    // Check if the packet is allowed in the filter cache
    struct filter_action *action = bpf_map_lookup_elem(&filter_cache, &key);
    if (!action) {
        DEBUG_PRINT("(ingress) Filter action not found for flow key");
        mark(skb, sizeof(outer_headers_t), MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    if (!action->ingress || !action->egress) {
        DEBUG_PRINT("(ingress) Filter action not allowed: ingress=%u, egress=%u",
                   action->ingress, action->egress);
        mark(skb, sizeof(outer_headers_t), MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    /** END: Forward Cache Validation */
    /** BEGIN: Reverse Cache Validation */
    // Check if mapping in egress cache L1 exists
    addr_t *host_dst_ip =
        bpf_map_lookup_elem(&egress_host_cache, &headers->inner.ip.saddr);
    if (!host_dst_ip) {
        DEBUG_PRINT(
            "(ingress) Host destination IP not found in egress_host_cache: %u",
            headers->inner.ip.saddr);
        mark(skb, sizeof(outer_headers_t), MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    /** END: Reverse Cache Validation */
    /** END: Step 2: Cache Retrieving */

    /** BEGIN: Step 3: Decapsulation and Intra-host Routing */
    int err = bpf_skb_adjust_room(
        skb, -(int)sizeof(outer_headers_t),
        BPF_ADJ_ROOM_MAC,  // shrink at the MAC (between L2 and L3) layer
        0);                // No flags needed since we're shrinking the skb
    if (err || skb->data_end < skb->data + sizeof(inner_headers_t)) {
        ERROR_PRINT("(ingress) Failed to adjust skb room: %d", err);
        return TC_ACT_OK;
    }

    // Set the inner headers
    inner_headers_t *inner = (inner_headers_t *)(skb->data);
    inner->eth = data->eth;

    // Redirect to the veth interface
    return bpf_redirect_peer(data->vindex, 0);
}

// License
// See https://eunomia.dev/en/tutorials/20-tc/
char __license[] SEC("license") = "GPL";
