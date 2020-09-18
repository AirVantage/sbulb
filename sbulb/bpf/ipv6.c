#include <linux/ipv6.h>
#include "sbulb/bpf/checksum.c"

typedef struct in6_addr ip_addr;

__attribute__((__always_inline__))
static inline bool compare_ip_addr(ip_addr *ipA, ip_addr *ipB) {
    for(int i = 0; i < 16 ; ++i)
        if (ipA->s6_addr[i] != ipB->s6_addr[i])
             return false;
    return true; 
}

__attribute__((__always_inline__))
static inline void copy_ip_addr(ip_addr * dest, ip_addr * src) {
    memcpy(dest,src,16);
}

__attribute__((__always_inline__))
static inline int parse_ip_header(struct ethhdr * eth, void * data_end, struct udphdr **udp, ip_addr ** saddr, ip_addr ** daddr) {
    // Handle only IPv6 packets
    if (eth->h_proto != bpf_htons(ETH_P_IPV6)) {
        return NOT_IP_V6;
    }

    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/ipv6.h
    struct ipv6hdr *iph;
    iph = (struct ipv6hdr *) (eth + 1);
    if ((void *) (iph + 1) > data_end) {
        return INVALID_IP_SIZE;
    }

    // Extract ip address
    (* saddr) = &iph->saddr;
    (* daddr) = &iph->daddr;

    // Handle only UDP traffic
    if (iph->nexthdr != IPPROTO_UDP) {
        return NOT_UDP;
    }

    // handle packet lifetime : https://tools.ietf.org/html/rfc8200#section-3
    if (iph->hop_limit <= 0)
       	return LIFETIME_EXPIRED;
    // TODO #15 we should maybe send an ICMP packet

    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/udp.h
    // Extract UDP header
    (*udp) = (struct udphdr *) (iph + 1);
    return 0;
}

__attribute__((__always_inline__))
static inline void update_ip_checksum(struct ethhdr * eth, void * data_end, ip_addr old_addr, ip_addr new_addr) {
    // no ip checksum in ipv6
}

__attribute__((__always_inline__))
static inline int update_udp_checksum(__u64 cs, ip_addr old_addr, ip_addr new_addr) {
    for(int i = 0; i < 4 ; ++i)
        update_csum(&cs , old_addr.s6_addr32[i], new_addr.s6_addr32[i]);
    return cs;
}

__attribute__((__always_inline__))
static inline void decrease_packet_lifetime(struct ethhdr * eth) {
    struct ipv6hdr *iph;
    iph = (struct ipv6hdr *) (eth + 1);
    --iph->hop_limit;
}
