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

// keys for association table.
struct associationKey {
    __be32 ipAddr; 
    __be16 port; 
};

// load balancer state.
struct state {
    int nextRS; // new real server index
};

// packet structure to log load balancing
struct packet {
    unsigned char dmac[ETH_ALEN];
    unsigned char smac[ETH_ALEN];
    __be32 daddr;
    __be32 saddr;
    int associationType; // 0:not set,1:new association, 2:existing association
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

// A map which contains virtual server IP address (__be32)
BPF_HASH(virtualServer, int, __be32, 1);
// A map which contains port to redirect
BPF_HASH(ports, __be16, int, 10); // TODO #5 make the max number of port configurable.
// maps which contains real server IP addresses (__be32)
BPF_HASH(realServersArray, int, __be32, 10); // TODO #5 make the max number of real server configurable.
BPF_HASH(realServersMap, __be32, __be32, 10); // TODO #5 make the max number of real server configurable.
// association tables : link a foreign peer to a real server IP address (__be12)
BPF_TABLE("lru_hash", struct associationKey, __be32, associationTable, 10000); // TODO #5 make the max number of association configurable.
// load balancer state
BPF_HASH(lbState, int, struct state, 1);

__attribute__((__always_inline__))
static inline __be32 * new_association(struct associationKey * k) {
    // Get index of real server which must handle this peer
    int zero = 0;
    struct state * state = lbState.lookup(&zero);
    int rsIndex = 0;
    if (state != NULL)
        rsIndex = state->nextRS;

    // Get real server from this index.
    __be32 * rsIp = realServersArray.lookup(&rsIndex);
    if (rsIp == NULL) {
        rsIndex = 0; // probably index out of bound so we restart from 0
        rsIp = realServersArray.lookup(&rsIndex);
        if (rsIp == NULL)
            return NULL; // XDP_ABORTED ?
    }

    // Update state (increment real server index)
    struct state newState = {};
    newState.nextRS = rsIndex + 1;
    lbState.update(&zero, &newState);

    // Create new association
    associationTable.update(k, rsIp);

    return rsIp;
}

int xdp_prog(struct xdp_md *ctx) {

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/if_ether.h
    struct ethhdr * eth = data;
    if ((void *) (eth + 1) > data_end)
        return XDP_DROP;

    // Handle only IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/ip.h
    struct iphdr *iph;
    iph = (struct iphdr *) (eth + 1);
    if ((void *) (iph + 1) > data_end)
        return XDP_DROP;
    // Minimum valid header length value is 5.
    // see (https://tools.ietf.org/html/rfc791#section-3.1)
    if (iph->ihl < 5)
        return XDP_DROP;
    // We only handle UDP traffic
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;
    // IP header size is variable because of options field.
    // see (https://tools.ietf.org/html/rfc791#section-3.1)
    //if ((void *) iph + iph->ihl * 4 > data_end)
    //    return XDP_DROP;
    // TODO #16 support IP header with variable size
    if (iph->ihl != 5) 
        return XDP_PASS;
    // Do not support fragmented packets
    if (iph->frag_off & IP_FRAGMENTED) 
        return XDP_PASS; // TODO #17 should we support it ?
    // TODO #15 we should drop packet with ttl = 0

    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/udp.h
    struct udphdr *udp;
    // TODO #16 support IP header with variable size
    //udp = (void *) iph + iph->ihl * 4;
    udp = (struct udphdr *) (iph + 1);
    if ((void *) (udp + 1) > data_end)
        return XDP_DROP;

    // Get virtual server
    int zero =  0;
    __be32 * vsIp = virtualServer.lookup(&zero);
    if (vsIp == NULL)
        return XDP_PASS;

    // Just for log, to know if we create new association or not
    int associationType = 2;  // 0:not set,1:new association, 2:existing association
    // Is it ingress traffic ? destination IP == VIP
    __be32 old_addr;
    __be32 new_addr;
    if (iph->daddr == *vsIp) {
        // do not handle traffic on ports we don't want to redirect
        if (!ports.lookup(&(udp->dest))) {
            return XDP_PASS;
        } else {
            // Log packet before
            struct packet pkt = {};
            memcpy(&pkt, data, sizeof(pkt)); // crappy
            pkt.daddr = iph->daddr;  
            pkt.saddr = iph->saddr;
            pkt.associationType = 0;
            events.perf_submit(ctx,&pkt,sizeof(pkt));

            // Handle ingress traffic
            // Find real server associated
            struct associationKey k = {};
            k.ipAddr = iph->saddr; 
            k.port = udp->source;
            __be32 * rsIp = associationTable.lookup(&k);
            // Create association if no real server associated
            // (or if real server associated does not exist anymore)
            if (rsIp == NULL || realServersMap.lookup(rsIp) == NULL) {
                rsIp = new_association(&k);
                if (rsIp     == NULL) 
                    return XDP_DROP; // XDP_ABORTED ?
                associationType = 1;
            }
            // Should not happened, mainly needed to make verfier happy
            if (rsIp == NULL) {
                return XDP_DROP; // XDP_ABORTED ?
            }

            // Update eth addr
            // Use virtual server MAC address (so packet destination) as source
            memcpy(eth->h_source, pkt.dmac, 6); 
            // Use source ethernet address as destination,
            // as we supose all ethernet traffic goes through this gateway.
            // (currently we support use case with only 1 ethernet gateway)
            memcpy(eth->h_dest, pkt.smac, 6); 

            // Update IP address (DESTINATION NAT)
            old_addr = iph->daddr;
            new_addr = *rsIp;
            iph->daddr = *rsIp; // use real server IP address as destination

            // TODO #15 we should probably decrement ttl too
        }
    } else {
        // Is it egress traffic ? source ip == a real server IP
        __be32 * rsIp = realServersMap.lookup(&iph->saddr);
        if (rsIp != NULL) {
            // do not handle traffic on ports we don't want to redirect
            if (!ports.lookup(&(udp->source))) {
                return XDP_PASS;
            } else {
                // Log packet before
                struct packet pkt = {};
                memcpy(&pkt, data, sizeof(pkt)); // crappy
                pkt.daddr = iph->daddr;  
                pkt.saddr = iph->saddr;
                pkt.associationType = 0;
                events.perf_submit(ctx,&pkt,sizeof(pkt));

                // Handle egress traffic
                // Find real server associated to this foreign peer
                struct associationKey k = {};
                k.ipAddr = iph->daddr; 
                k.port = udp->dest;
                __be32 * currentRsIp = associationTable.lookup(&k);
                // Create association if no real server associated
                // (or if real server associated does not exist anymore)
                if (currentRsIp == NULL ||  realServersMap.lookup(currentRsIp) == NULL ) {
                    currentRsIp = new_association(&k);
                    if (currentRsIp == NULL)
                        return XDP_DROP; // XDP_ABORTED ?
                    associationType = 1;  
                } else if (*currentRsIp != *rsIp) {
                    // If there is an association
                    // only associated server is allow to send packet
                    return XDP_DROP;
                }
                
                // Update eth addr
                // Use virtual server MAC address (so packet destination) as source
                memcpy(eth->h_source, pkt.dmac, 6);
                // Use source ethernet address as destination,
                // as we supose all ethernet traffic goes through this gateway.
                // (currently we support use case with only 1 ethernet gateway)
                memcpy(eth->h_dest, pkt.smac, 6);

                // Update IP address (SOURCE NAT)
                old_addr = iph->saddr;
                new_addr = *vsIp;
                iph->saddr = *vsIp; // use virtual server IP address as source

                // TODO #15 we should probably decrement ttl too
            }
        } else {
            return XDP_PASS;
        }
    }
  
    // Update IP checksum
    // TODO #16 support IP header with variable size
    iph->check = 0;
    __u64 cs = 0 ;
    // TODO #7 consider to use incremental update checksum here too.
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
    pkt.associationType = associationType;
    events.perf_submit(ctx,&pkt,sizeof(pkt));

    return XDP_TX;
}
