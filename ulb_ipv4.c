#include <linux/ip.h>

typedef __be32 ip_addr;

/* 0x3FFF mask to check for fragment offset field */
#define IP_FRAGMENTED 65343

__attribute__((__always_inline__))
static inline bool compare_ip_addr(ip_addr *ipA, ip_addr *ipB) {
    return (* ipA) == (* ipB); 
}

__attribute__((__always_inline__))
static inline void copy_ip_addr(ip_addr * dest, ip_addr * src) {
    (* dest) = (*src);
}

__attribute__((__always_inline__))
static inline int parse_ip_header(struct ethhdr * eth, void * data_end, struct udphdr **udp, ip_addr ** saddr, ip_addr ** daddr) {

    // Handle only IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return NOT_IP_V4;
    }

    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/ip.h
    struct iphdr *iph;
    iph = (struct iphdr *) (eth + 1);
    if ((void *) (iph + 1) > data_end) {
        return INVALID_IP_SIZE;
    }

    // Extract ip address
    (* saddr) = &iph->saddr;
    (* daddr) = &iph->daddr;

    // Minimum valid header length value is 5.
    // see (https://tools.ietf.org/html/rfc791#section-3.1)
    if (iph->ihl < 5) {
        return TOO_SMALL_IP_HEADER;
    }

    // Handle only UDP traffic
    if (iph->protocol != IPPROTO_UDP) {
        return NOT_UDP;
    }

    // IP header size is variable because of options field.
    // see (https://tools.ietf.org/html/rfc791#section-3.1)
    // TODO #16 support IP header with variable size ?
    if (iph->ihl != 5) {
        return TOO_BIG_IP_HEADER;
    }

    // Do not support fragmented packets
    if (iph->frag_off & IP_FRAGMENTED) {
        return FRAGMENTED_IP_PACKET;
    }
    // TODO #15 we should drop packet with ttl = 0 for ipv4

    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/udp.h
    // Extract UDP header
    (*udp) = (struct udphdr *) (iph + 1);
    return 0;
}

__attribute__((__always_inline__))
static inline void update_ip_checksum(struct ethhdr * eth, void * data_end, ip_addr old_addr, ip_addr new_addr) {
    // TODO #16 support IP header with variable size
     struct iphdr *iph;
    iph = (struct iphdr *) (eth + 1);    
    iph->check = 0;
    __u64 cs = 0 ;
    // TODO #7 consider to use incremental update checksum here too.
    ipv4_csum(iph, sizeof (*iph), &cs);
    iph->check = cs;
}

__attribute__((__always_inline__))
static inline int update_udp_checksum(__u64 cs, ip_addr old_addr, ip_addr new_addr) {
    update_csum(&cs , old_addr, new_addr);
    return cs;
}

