#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* 0x3FFF mask to check for fragment offset field */
#define IP_FRAGMENTED 65343

// Real Server structure (IP address)
struct server {
    __be32 ipAddr; // TODO remove struct as now there is only 1 field
};

// packet structure to log load balancing
struct packet {
    unsigned char dmac[ETH_ALEN];
    unsigned char smac[ETH_ALEN];
    __be32 daddr;
    __be32 saddr;
};
BPF_PERF_OUTPUT(events);

__attribute__((__always_inline__))
static inline __u16 csum_fold_helper(__u64 csum) {
  int i;
  #pragma unroll
  for (i = 0; i < 4; i ++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

__attribute__((__always_inline__))
static inline void ipv4_csum_inline(void *iph, __u64 *csum) {
  __u16 *next_iph_u16 = (__u16 *)iph;
  #pragma clang loop unroll(full)
  for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
     *csum += *next_iph_u16++;
  }
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__))
static inline void ipv4_csum(void *data_start, int data_size,  __u64 *csum) {
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__))
static inline void ipv4_l4_csum(void *data_start, __u32 data_size,
                                __u64 *csum, struct iphdr *iph) {
  __u32 tmp = 0;
  *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
  *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
  tmp = __builtin_bswap32((__u32)(iph->protocol));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  tmp = __builtin_bswap32((__u32)(data_size));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

// Update checksum following RFC 1624 (Eqn. 3): https://tools.ietf.org/html/rfc1624
//     HC' = ~(~HC + ~m + m')
// Where :
//   HC  - old checksum in header
//   HC' - new checksum in header
//   m   - old value
//   m'  - new value
__attribute__((__always_inline__))
static inline void update_csum(__u64 *csum, __be32 old_addr,__be32 new_addr ) {
    // ~HC 
    *csum = ~*csum;
    *csum = *csum & 0xffff;
    // + ~m
    __u32 tmp;
    tmp = ~old_addr;
    *csum += tmp;
    // + m
    *csum += new_addr;
    // then fold and complement result ! 
    *csum = csum_fold_helper(*csum);
}

// A map which contains virtual server
BPF_HASH(virtualServer, int, struct server, 1); 
// A map which contains port to redirect
BPF_HASH(ports, __be16, int, 10); // TODO how to we handle the max number of port we support.
// maps which contains real server 
BPF_HASH(realServersArray, int, struct server, 10); // TODO how to we handle the max number of real server.
BPF_HASH(realServersMap, __be32, struct server, 10); // TODO how to we handle the max number of real server.

int xdp_prog(struct CTXTYPE *ctx) {

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/if_ether.h
    struct ethhdr * eth = data;
    if (eth + 1 > data_end)
        return XDP_DROP;

    // Handle only IP packets (v4?)
    if (eth->h_proto != bpf_htons(ETH_P_IP)){
        return XDP_PASS;
    }

    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/ip.h
    struct iphdr *iph;
    iph = eth + 1;
    if (iph + 1 > data_end)
        return XDP_DROP;
    // Minimum valid header length value is 5.
    // see (https://tools.ietf.org/html/rfc791#section-3.1)
    if (iph->ihl < 5)
        return XDP_DROP;
    // IP header size is variable because of options field.
    // see (https://tools.ietf.org/html/rfc791#section-3.1)
    //if ((void *) iph + iph->ihl * 4 > data_end)
    //    return XDP_DROP;
    // TODO support IP header with variable size
    if (iph->ihl != 5) 
        return XDP_PASS;
    // Do not support fragmented packets as L4 headers may be missing
    if (iph->frag_off & IP_FRAGMENTED) 
        return XDP_PASS; // TODO should we support it ?
    // TODO we should drop packet with ttl = 0

    // We only handle UDP traffic
    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }
    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/udp.h
    struct udphdr *udp;
    //udp = (void *) iph + iph->ihl * 4;
    udp = iph + 1;
    if (udp + 1 > data_end)
        return XDP_DROP;
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < 8)
        return XDP_DROP;
    if (udp_len > 512) // TODO use a more approriate max value
        return XDP_DROP;
    udp_len = udp_len & 0x1ff;
    if ((void *) udp + udp_len > data_end)
        return XDP_DROP;
    // Get virtual server
    int zero =  0;
    struct server * vs = virtualServer.lookup(&zero);
    if (vs == NULL) {
	return XDP_PASS;
    }
    // Is it ingress traffic ? destination IP == VIP
    __be32 old_addr;
    __be32 new_addr;
    if (iph->daddr == vs->ipAddr) {
        if (!ports.lookup(&(udp->dest))) {
            return XDP_PASS;
        } else {
            // Log packet before
            struct packet pkt = {};
            memcpy(&pkt, data, sizeof(pkt)); // crappy
            pkt.daddr = iph->daddr;  
            pkt.saddr = iph->saddr;
            events.perf_submit(ctx,&pkt,sizeof(pkt));

            // handle ingress traffic
            // TODO support several real server
            int i = 0;
            struct server * rs = realServersArray.lookup(&i);
            if (rs == NULL) {
                return XDP_PASS;
            }

            // update eth addr
            memcpy(eth->h_source, pkt.dmac, 6); // use virtual server MAC address as source
            memcpy(eth->h_dest, pkt.smac, 6); // we support only one ethernet gateway (we support only one ethernet gateway (so all ethernet traffic should pass thought it)

            // update IP address
            old_addr = iph->daddr;
            new_addr = rs->ipAddr;
            iph->daddr = rs->ipAddr; // use real server IP address as destination

            // TODO should we update id ? 
            //iph->id = iph->id + 1;

            // TODO we should probably decrement ttl too
        }
    } else
    // Is it egress traffic ? source ip == a real server IP
    if (realServersMap.lookup(&iph->saddr)) {
        if (!ports.lookup(&(udp->source))) {
            return XDP_PASS;
        } else {
            // Log packet before
            struct packet pkt = {};
            memcpy(&pkt, data, sizeof(pkt)); // crappy
            pkt.daddr = iph->daddr;  
            pkt.saddr = iph->saddr;
            events.perf_submit(ctx,&pkt,sizeof(pkt));

            // handle egress traffic
            // update eth addr
            memcpy(eth->h_source, pkt.dmac, 6); // use virtual server MAC address as source
            memcpy(eth->h_dest, pkt.smac, 6); // we support only one ethernet gateway (so all ethernet traffic should pass thought it)

            // update IP address
            old_addr = iph->saddr;
            new_addr = vs->ipAddr;
            iph->saddr = vs->ipAddr; // use virtual server IP address as source


            // TODO should we update id ? 
            //iph->id = iph->id + 1 ;

            // TODO we should probably decrement ttl too
        }
    } else {
        return XDP_PASS;
    }
  
    // Update IP checksum
    // TODO support IP header with variable size
    iph->check = 0;
    __u64 cs = 0 ;
    // TODO We should consider to use incremental update checksum here too.
    ipv4_csum(iph, sizeof (*iph), &cs);
    iph->check = cs;

    // Update UDP checksum
    cs = udp->check;
    update_csum(&cs , old_addr, new_addr);
    udp->check = cs;

    // Log packet after
    struct packet pkt = {};
    memcpy(&pkt, data, sizeof(pkt)); // crappy
    pkt.daddr = iph->daddr;
    pkt.saddr = iph->saddr;
    events.perf_submit(ctx,&pkt,sizeof(pkt));

    return XDP_TX;
}
