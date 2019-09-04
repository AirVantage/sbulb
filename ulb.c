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

// Log structure
struct logEvent {
    // code identifing the kind of events
    int code;
    // old/original packet addresses
    unsigned char odmac[ETH_ALEN];
    unsigned char osmac[ETH_ALEN];
    __be32 odaddr;
    __be32 osaddr;
    // new/modified packet addresses
    unsigned char ndmac[ETH_ALEN];
    unsigned char nsmac[ETH_ALEN];
    __be32 ndaddr;
    __be32 nsaddr;    
};
BPF_PERF_OUTPUT(logs);
// Logging function
__attribute__((__always_inline__))
static inline void log(unsigned char level, struct xdp_md *ctx, unsigned char code, struct logEvent * logEvent) {
    if (level >= LOGLEVEL) {
        logEvent->code = code;
        logs.perf_submit(ctx, logEvent, sizeof(*logEvent));
    }
}

// Checksum utilities
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
BPF_HASH(ports, __be16, int, MAX_PORTS);
// maps which contains real server IP addresses (__be32)
BPF_HASH(realServersArray, int, __be32, MAX_REALSERVERS);
BPF_HASH(realServersMap, __be32, __be32, MAX_REALSERVERS);
// association tables : link a foreign peer to a real server IP address (__be12)
BPF_TABLE("lru_hash", struct associationKey, __be32, associationTable, MAX_ASSOCIATIONS);
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

    void *data = (void *)(long)ctx->data;         // begin of the packet
    void *data_end = (void *)(long)ctx->data_end; // end of the packet
    struct logEvent logEvent = {};                // stucture used to log
    
    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/if_ether.h
    struct ethhdr * eth = data;
    if ((void *) (eth + 1) > data_end) {
        log(WARNING, ctx, INVALID_ETH_SIZE, &logEvent);
        return XDP_DROP;
    }

    // Handle only IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        log(TRACE, ctx, NOT_IP_V4, &logEvent);
        return XDP_PASS;
    }

    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/ip.h
    struct iphdr *iph;
    iph = (struct iphdr *) (eth + 1);
    if ((void *) (iph + 1) > data_end) {
        log(WARNING, ctx, INVALID_IP_SIZE, &logEvent);
        return XDP_DROP;
    }
    
    // Store packet addresses for logging
    memcpy(&logEvent.odmac, eth->h_dest, ETH_ALEN);
    memcpy(&logEvent.osmac, eth->h_source, ETH_ALEN);
    logEvent.odaddr = iph->daddr;
    logEvent.osaddr = iph->saddr;

    // Minimum valid header length value is 5.
    // see (https://tools.ietf.org/html/rfc791#section-3.1)
    if (iph->ihl < 5) {
        log(WARNING, ctx, TOO_SMALL_IP_HEADER, &logEvent);
        return XDP_DROP;
    }
    // We only handle UDP traffic
    if (iph->protocol != IPPROTO_UDP) {
        log(TRACE, ctx, NOT_UDP, &logEvent);
        return XDP_PASS;
    }
    // IP header size is variable because of options field.
    // see (https://tools.ietf.org/html/rfc791#section-3.1)
    //if ((void *) iph + iph->ihl * 4 > data_end)
    //    return XDP_DROP;
    // TODO #16 support IP header with variable size
    if (iph->ihl != 5) {
        log(INFO, ctx, TOO_BIG_IP_HEADER, &logEvent);
        return XDP_PASS;
    }
    // Do not support fragmented packets
    if (iph->frag_off & IP_FRAGMENTED) {
        log(INFO, ctx, FRAGMENTED_IP_PACKET, &logEvent);
        return XDP_PASS; // TODO #17 should we support it ?
    }
    // TODO #15 we should drop packet with ttl = 0

    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/udp.h
    struct udphdr *udp;
    // TODO #16 support IP header with variable size
    //udp = (void *) iph + iph->ihl * 4;
    udp = (struct udphdr *) (iph + 1);
    if ((void *) (udp + 1) > data_end) {
        log(WARNING, ctx, INVALID_UDP_SIZE, &logEvent);
        return XDP_DROP;
    }

    // Get virtual server
    int zero =  0;
    __be32 * vsIp = virtualServer.lookup(&zero);
    if (vsIp == NULL) {
        log(ERROR, ctx, NO_VIRTUAL_SERVER, &logEvent);
        return XDP_PASS;
    }

    // Store ip address modification for checksum incremental update
    __be32 old_addr;
    __be32 new_addr;

    // Is it ingress traffic ? destination IP == VIP
    if (iph->daddr == *vsIp) {
        // do not handle traffic on ports we don't want to redirect
        if (!ports.lookup(&(udp->dest))) {
            log(TRACE, ctx, INGRESS_NOT_HANDLED_PORT, &logEvent);
            return XDP_PASS;
        } else {
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
                if (rsIp == NULL) {
                    log(ERROR, ctx, INGRESS_CANNOT_CREATE_ASSO, &logEvent);
                    return XDP_DROP; // XDP_ABORTED ?
                }
                logEvent.code = INGRESS_NEW_NAT;
            } else {
                logEvent.code = INGRESS_REUSED_NAT;
            }
            // Should not happened, mainly needed to make verfier happy
            if (rsIp == NULL) {
                log(CRITICAL, ctx, INGRESS_CANNOT_CREATE_ASSO2, &logEvent);
                return XDP_DROP; // XDP_ABORTED ?
            }

            // Eth address swapping
            unsigned char dmac[ETH_ALEN];
            memcpy(eth->h_dest, dmac, ETH_ALEN);             
            // Use virtual server MAC address (so packet destination) as source
            memcpy(eth->h_source, eth->h_dest, ETH_ALEN); 
            // Use source ethernet address as destination,
            // as we supose all ethernet traffic goes through this gateway.
            // (currently we support use case with only 1 ethernet gateway)
            memcpy(eth->h_source, dmac, ETH_ALEN);

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
                log(TRACE, ctx, EGRESS_NOT_HANDLED_PORT, &logEvent);
                return XDP_PASS;
            } else {
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
                    if (currentRsIp == NULL) {
                        log(ERROR, ctx, EGRESS_CANNOT_CREATE_ASSO, &logEvent);
                        return XDP_DROP; // XDP_ABORTED ?
                    }
                    logEvent.code = EGRESS_NEW_NAT;
                } else if (*currentRsIp != *rsIp) {
                    // If there is an association
                    // only associated server is allow to send packet
                    log(INFO, ctx, EGRESS_NOT_AUTHORIZED, &logEvent);
                    return XDP_DROP;
                } else {
                    logEvent.code = EGRESS_REUSED_NAT;
                }
                
                // Eth address swapping
                unsigned char dmac[ETH_ALEN];
                memcpy(eth->h_dest, dmac, ETH_ALEN);       
                // Use virtual server MAC address (so packet destination) as source
                memcpy(eth->h_source, eth->h_dest, ETH_ALEN); 
                // Use source ethernet address as destination,
                // as we supose all ethernet traffic goes through this gateway.
                // (currently we support use case with only 1 ethernet gateway)
                memcpy(eth->h_source, dmac, ETH_ALEN);

                // Update IP address (SOURCE NAT)
                old_addr = iph->saddr;
                new_addr = *vsIp;
                iph->saddr = *vsIp; // use virtual server IP address as source

                // TODO #15 we should probably decrement ttl too
            }
        } else {
            // neither ingress(destIP=VirtualServerIP) nor egress(sourceIP=RealServerIP) traffic
            log(TRACE, ctx, UNHANDLED_TRAFFIC, &logEvent);
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

    // Log address translation
    // Store new addresses
    memcpy(&logEvent.ndmac, eth->h_dest, ETH_ALEN);
    memcpy(&logEvent.nsmac, eth->h_source, ETH_ALEN);
    logEvent.ndaddr = iph->daddr;
    logEvent.nsaddr = iph->saddr;
    log(DEBUG, ctx, logEvent.code, &logEvent);

    return XDP_TX;
}
