#include <linux/bpf.h>
#include <linux/if_ether.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* 0x3FFF mask to check for fragment offset field */
#define IP_FRAGMENTED 65343

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif
#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

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

__section("prog")
int xdp_prog(struct xdp_md *ctx) {
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
    //udp_len = udp_len & 0x1ff;
    if ((void *) udp + udp_len > data_end)
        return XDP_DROP;
    
    // Is it ingress traffic ? destination IP == VIP
    /*if (iph->daddr == VIP) {
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
            struct server * server = realServers.lookup(&i);
            if (server == NULL) {
                return XDP_PASS;
            }
            memcpy(eth->h_dest, server->macAddr, 6);
            iph->daddr = server->ipAddr;
        }
    } else
    // Is it egress traffic ? source IP == VIP
    if (iph->saddr == VIP) {
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
            // TODO support several real server
            int i = 0;
            struct server * server = realServers.lookup(&i);
            if (server == NULL) {
                return XDP_PASS;
            }
            memcpy(eth->h_source, server->macAddr, 6);
            iph->saddr = server->ipAddr;
        }
    } else {
        return XDP_PASS;
    }*/
  
    // Update IP checksum
    // TODO support IP header with variable size
    iph->check = 0;
    __u64 cs = 0 ;
    ipv4_csum(iph, sizeof (*iph), &cs);
    iph->check = cs;

    // Update UDP checksum
    udp->check = 0;
    cs = 0;
    ipv4_l4_csum(udp, udp_len, &cs, iph) ;
    udp->check = cs;

    return XDP_PASS;
}

char __license[] __section("license") = "GPL";
