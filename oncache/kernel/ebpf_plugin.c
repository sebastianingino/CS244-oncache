#include "ebpf_plugin.h"

// Maximum number of entries in the caches
#define MAX_ENTRIES 1024

// Interface map size
#define INTERFACE_MAP_SIZE 16

// Marker for missed packets (note: first 2 bits are reserved for ECN)
#define MISSED_MARK (1 << 2)
// Marker for established flows (note: first 2 bits are reserved for ECN)
#define EST_MARK (1 << 3)

// Minimum recommended UDP port for VXLAN
// See: https://datatracker.ietf.org/doc/html/rfc7348#section-5
#define VXLAN_UDP_PORT 49152
// Maximum recommended UDP port for VXLAN
// See: https://datatracker.ietf.org/doc/html/rfc7348#section-5
#define VXLAN_UDP_PORT_MAX 65535

#define DEBUG
// Enable debug prints
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

// Ingress cache: container destination IP -> (veth interface index, inner MAC
// header)
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
    DEBUG_PRINT("egress_init called\n");

    /** BEGIN: Packet Validation */
    // Check if the skb is long enough
    // Note: we expect encapsulation since we're attached to the host interface
    // Additional note: we have to check skb->data_end and skb->data without
    // subtraction due to the verifier not liking it otherwise.
    // Additional note: we don't need to check for a NULL pointer since the
    // we're guaranteed that skb->data is not NULL.
    if (skb->data_end < skb->data + sizeof(encap_headers_t)) {
        DEBUG_PRINT("skb is not large enough\n");
        return TC_ACT_OK;
    }

    // Get the headers
    encap_headers_t *headers = (encap_headers_t *)(skb->data);

    // Check if the outer packet is a VXLAN packet
    if (!is_vxlan_pkt(headers)) {
        DEBUG_PRINT("Not a VXLAN packet\n");
        return TC_ACT_OK;
    }

    // Get flow key and check if inner packet is long enough
    struct flow_key key;
    if (!to_flow_key(&headers->inner, skb, &key)) {
        DEBUG_PRINT("Failed to create flow key\n");
        return TC_ACT_OK;
    }

    // Check if the packet is marked as missed
    if (!has_mark(&headers->inner, MISSED_MARK)) {
        DEBUG_PRINT("Packet not marked as missed\n");
        return TC_ACT_OK;
    }

    // Check if the packet is marked as established
    if (!has_mark(&headers->inner, EST_MARK)) {
        DEBUG_PRINT("Packet not marked as established\n");
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
    mark(&headers->inner, MISSED_MARK, 0);
    mark(&headers->inner, EST_MARK, 0);

    return TC_ACT_OK;
}

// Egress hook (called before egress_init)
// Attached to outgoing packets, host veth interface
SEC("tc/egress")
int egress(struct __sk_buff *skb) {
    DEBUG_PRINT("egress called\n");

    /** BEGIN: Packet Validation */
    // Check if the skb is long enough
    // Note: NO encapsulation since we're attached to the host veth
    if (skb->data_end < skb->data + sizeof(inner_headers_t)) {
        DEBUG_PRINT("skb is not large enough\n");
        return TC_ACT_OK;
    }
    // Get the headers
    inner_headers_t *headers = (inner_headers_t *)(skb->data);

    // Get flow key and check if the packet is long enough
    struct flow_key key;
    if (!to_flow_key(headers, skb, &key)) {
        DEBUG_PRINT("Failed to create flow key\n");
        return TC_ACT_OK;
    }
    /** END: Packet Validation */

    /** BEGIN: Step 1: Cache Retrieving */
    /** BEGIN: Forward Cache Validation */
    // Check if mapping in egress cache L1 exists
    addr_t *host_dst_ip =
        bpf_map_lookup_elem(&egress_host_cache, &headers->ip.daddr);
    if (!host_dst_ip) {
        DEBUG_PRINT("Host destination IP not found in egress_host_cache\n");
        mark(headers, MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    // Check if mapping in egress cache L2 exists
    struct egress_data *data =
        bpf_map_lookup_elem(&egress_data_cache, host_dst_ip);
    if (!data) {
        DEBUG_PRINT("Egress data not found for host destination IP: %u\n",
                    *host_dst_ip);
        mark(headers, MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    // Check if the packet is allowed in the filter cache
    struct filter_action *action = bpf_map_lookup_elem(&filter_cache, &key);
    if (!action) {
        DEBUG_PRINT("Filter action not found for flow key\n");
        mark(headers, MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    if (!action->egress || !action->ingress) {
        DEBUG_PRINT("Filter action not allowed: ingress=%u, egress=%u\n",
                    action->ingress, action->egress);
        mark(headers, MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    /** END: Forward Cache Validation */

    /** BEGIN: Reverse Cache Validation */
    struct ingress_data *ingress_data =
        bpf_map_lookup_elem(&ingress_cache, &headers->ip.daddr);
    if (!ingress_data) {
        DEBUG_PRINT("Ingress data not found for IP: %u\n", headers->ip.daddr);
        mark(headers, MISSED_MARK, 1);
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
    if (err || skb->data_end < skb->data + sizeof(outer_headers_t)) {
        ERROR_PRINT("Failed to adjust skb room: %d\n", err);
        return TC_ACT_OK;
    }

    // Set the outer headers
    outer_headers_t *outer = (outer_headers_t *)(skb->data);
    *outer = data->outer;
    // Update the UDP length
    outer->udp.len =
        bpf_htons(skb->len - sizeof(struct ethhdr) - sizeof(struct iphdr));
    // Update the IP length and checksum
    __u16 old_len = outer->ip.tot_len;
    __u16 new_len = skb->len - sizeof(struct ethhdr);
    outer->ip.tot_len = bpf_htons(new_len);
    // L3 checksum replacement is incremental
    // See: https://docs.ebpf.io/linux/helper-function/bpf_l3_csum_replace/
    // Note: this makes me sad
    bpf_l3_csum_replace(skb,
                        sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                        old_len, new_len, sizeof(__u16));

    // Re-check length due to L3 checksum replacement invalidating pointers
    if (skb->data_end <
        skb->data + sizeof(outer_headers_t) + sizeof(inner_headers_t)) {
        ERROR_PRINT("Failed to re-check skb length\n");
        return TC_ACT_OK;
    }

    // Get headers
    outer = (outer_headers_t *)(skb->data);
    inner_headers_t *inner =
        (inner_headers_t *)(skb->data + sizeof(outer_headers_t));

    // Set inner MAC header
    inner->eth = data->inner;

    // Update the UDP source port
    __u32 hash = bpf_get_hash_recalc(skb);
    __be16 src_port = bpf_htons(VXLAN_UDP_PORT +
                                (hash % (VXLAN_UDP_PORT_MAX - VXLAN_UDP_PORT)));
    outer->udp.source = src_port;

    return bpf_redirect(data->ifindex, 0);
}

// Ingress init hook
// Attached to incoming packets, container veth interface
SEC("tc/ingress_init")
int ingress_init(struct __sk_buff *skb) {
    DEBUG_PRINT("ingress_init called\n");

    /** BEGIN: Packet Validation */
    // Check if the skb is valid and is long enough
    // Note: NO encapsulation since we're attached to the container veth
    if (skb->data_end < skb->data + sizeof(inner_headers_t)) {
        DEBUG_PRINT("skb is not large enough\n");
        return TC_ACT_OK;
    }

    // Get the headers
    inner_headers_t *headers = (inner_headers_t *)(skb->data);

    // Get flow key and check if the packet is long enough
    struct flow_key key;
    if (!to_flow_key(headers, skb, &key)) {
        DEBUG_PRINT("Failed to create flow key\n");
        return TC_ACT_OK;
    }

    // Check if the packet is marked as missed
    if (!has_mark(headers, MISSED_MARK)) {
        DEBUG_PRINT("Packet not marked as missed\n");
        return TC_ACT_OK;
    }
    // Check if the packet is marked as established
    if (!has_mark(headers, EST_MARK)) {
        DEBUG_PRINT("Packet not marked as established\n");
        return TC_ACT_OK;
    }
    /** END: Packet Validation */

    /** BEGIN: Check Daemon State */
    // Note: container destination IP -> veth index is maintained by the daemon
    // and must exist ahead of time
    struct ingress_data *data =
        bpf_map_lookup_elem(&ingress_cache, &headers->ip.daddr);
    if (!data) {
        DEBUG_PRINT("Ingress data not found for IP: %u\n", headers->ip.daddr);
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
    mark(headers, MISSED_MARK, 0);
    mark(headers, EST_MARK, 0);

    return TC_ACT_OK;
}

// Ingress hook (called before ingress_init)
// Attached to incoming packets, host interface
SEC("tc/ingress")
int ingress(struct __sk_buff *skb) {
    DEBUG_PRINT("ingress called\n");

    /** BEGIN: Packet Validation */
    // Check if the skb is valid and is long enough
    // Note: we expect encapsulation since we're attached to the host interface
    if (skb->data_end < skb->data + sizeof(encap_headers_t)) {
        DEBUG_PRINT("skb is not large enough\n");
        return TC_ACT_OK;
    }

    // Get the headers
    encap_headers_t *headers = (encap_headers_t *)(skb->data);

    // Check if the outer packet is a VXLAN packet
    if (!is_vxlan_pkt(headers)) {
        DEBUG_PRINT("Not a VXLAN packet\n");
        return TC_ACT_OK;
    }

    // Get flow key and check if the inner packet is long enough
    struct flow_key key;
    if (!to_flow_key(&headers->inner, skb, &key)) {
        DEBUG_PRINT("Failed to create flow key\n");
        return TC_ACT_OK;
    }

    /** BEGIN: Step 1: Destination Check */
    /** BEGIN: Interface Validation */
    // Get the interface data
    if (host_interface.ip == 0) {
        DEBUG_PRINT("Host interface not initialized\n");
        return TC_ACT_OK;
    }
    // Check if the packet matches the interface data
    if (!equal_buf(host_interface.mac, headers->outer.eth.h_dest, ETH_ALEN)) {
        DEBUG_PRINT("Packet does not match interface eth address\n");
        return TC_ACT_OK;
    }
    if (host_interface.ip != headers->outer.ip.daddr) {
        DEBUG_PRINT("Packet does not match interface IP address\n");
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
        DEBUG_PRINT("Ingress data not found for IP: %u\n",
                    headers->inner.ip.daddr);
        mark(&headers->inner, MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    // Check if the packet is allowed in the filter cache
    struct filter_action *action = bpf_map_lookup_elem(&filter_cache, &key);
    if (!action) {
        DEBUG_PRINT("Filter action not found for flow key\n");
        mark(&headers->inner, MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    if (!action->ingress || !action->egress) {
        DEBUG_PRINT("Filter action not allowed: ingress=%u, egress=%u\n",
                    action->ingress, action->egress);
        mark(&headers->inner, MISSED_MARK, 1);
        return TC_ACT_OK;
    }
    /** END: Forward Cache Validation */
    /** BEGIN: Reverse Cache Validation */
    // Check if mapping in egress cache L1 exists
    addr_t *host_dst_ip =
        bpf_map_lookup_elem(&egress_host_cache, &headers->inner.ip.daddr);
    if (!host_dst_ip) {
        DEBUG_PRINT("Host destination IP not found in egress_host_cache\n");
        mark(&headers->inner, MISSED_MARK, 1);
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
        ERROR_PRINT("Failed to adjust skb room: %d\n", err);
        return TC_ACT_OK;
    }

    // Set the inner headers
    inner_headers_t *inner = (inner_headers_t *)(skb->data);
    __builtin_memcpy(inner->eth.h_dest, data->eth.h_dest, ETH_ALEN);
    __builtin_memcpy(inner->eth.h_source, data->eth.h_source, ETH_ALEN);
    return bpf_redirect_peer(data->vindex, 0);
}

// License
// See https://eunomia.dev/en/tutorials/20-tc/
char __license[] SEC("license") = "GPL";
