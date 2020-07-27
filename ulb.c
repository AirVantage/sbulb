#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/udp.h>

// include ip handling util
#ifdef IPV6
#include "ulb_ipv6.c"
#else
#include "ulb_ipv4.c"
#endif

// keys for association table.
struct associationKey {
    ip_addr ipAddr;
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
    ip_addr odaddr;
    ip_addr osaddr;
    // new/modified packet addresses
    unsigned char ndmac[ETH_ALEN];
    unsigned char nsmac[ETH_ALEN];
    ip_addr ndaddr;
    ip_addr nsaddr;
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

// A map which contains virtual server IP address
BPF_HASH(virtualServer, int, ip_addr, 1);
// A map which contains port to redirect
BPF_HASH(ports, __be16, int, MAX_PORTS);
// maps which contains real server IP addresses
BPF_HASH(realServersArray, int, ip_addr, MAX_REALSERVERS);
BPF_HASH(realServersMap, ip_addr, ip_addr, MAX_REALSERVERS);
// association tables : link a foreign peer to a real server IP address
BPF_TABLE("lru_hash", struct associationKey, ip_addr, associationTable, MAX_ASSOCIATIONS);
// load balancer state
BPF_HASH(lbState, int, struct state, 1);

__attribute__((__always_inline__))
static inline ip_addr * new_association(struct associationKey * k) {
    // Get index of real server which must handle this peer
    int zero = 0;
    struct state * state = lbState.lookup(&zero);
    int rsIndex = 0;
    if (state != NULL)
        rsIndex = state->nextRS;

    // Get real server from this index.
    ip_addr * rsIp = realServersArray.lookup(&rsIndex);
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
    if (associationTable.update(k, rsIp))
        return NULL; // XDP_ABORTED ?

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

    // Parse IP header : extract ip address & udp header
    struct udphdr * udp = NULL;
    ip_addr * saddr = NULL;
    ip_addr * daddr = NULL;
    int res = parse_ip_header(eth, data_end, &udp, &saddr, &daddr);
    // Store packet addresses for logging
    if (saddr != NULL && daddr != NULL) {
        memcpy(&logEvent.odmac, eth->h_dest, ETH_ALEN);
        memcpy(&logEvent.osmac, eth->h_source, ETH_ALEN);
        copy_ip_addr(&logEvent.odaddr, daddr);
        copy_ip_addr(&logEvent.osaddr, saddr);
    }
    // Handle ip header error
    if (udp == NULL){
        switch(res) {
            case NOT_IP_V4 :
            case NOT_IP_V6 :
            case NOT_UDP :
                log(TRACE, ctx, res, &logEvent);
                return XDP_PASS;
            case FRAGMENTED_IP_PACKET:
            case TOO_BIG_IP_HEADER:
                log(INFO, ctx, res, &logEvent);
                return XDP_PASS;
            case INVALID_IP_SIZE :
            case TOO_SMALL_IP_HEADER:
                log(WARNING, ctx, res, &logEvent);
                return XDP_DROP;
            default :
                log(ERROR, ctx, res, &logEvent);
                return XDP_PASS;
        }
    }

    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/udp.h
    if ((void *) (udp + 1) > data_end) {
        log(WARNING, ctx, INVALID_UDP_SIZE, &logEvent);
        return XDP_DROP;
    }

    // Get virtual server
    int zero =  0;
    ip_addr * vsIp = virtualServer.lookup(&zero);
    if (vsIp == NULL) {
        log(ERROR, ctx, NO_VIRTUAL_SERVER, &logEvent);
        return XDP_PASS;
    }

    // Store ip address modification for checksum incremental update
    ip_addr old_addr;
    __builtin_memset(&old_addr, 0, sizeof(old_addr));
    ip_addr new_addr;
    __builtin_memset(&new_addr, 0, sizeof(new_addr));

    // Is it ingress traffic ? destination IP == VIP
    if (compare_ip_addr(daddr, vsIp)) {
        // do not handle traffic on ports we don't want to redirect
        if (!ports.lookup(&(udp->dest))) {
            log(TRACE, ctx, INGRESS_NOT_HANDLED_PORT, &logEvent);
            return XDP_PASS;
        } else {
            // Handle ingress traffic
            // Find real server associated
            struct associationKey k = {};
            copy_ip_addr(&k.ipAddr, saddr);
            k.port = udp->source;
            ip_addr * rsIp = associationTable.lookup(&k);
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
            memcpy(dmac, eth->h_dest, ETH_ALEN);             
            // Use virtual server MAC address (so packet destination) as source
            memcpy(eth->h_dest, eth->h_source, ETH_ALEN); 
            // Use source ethernet address as destination,
            // as we supose all ethernet traffic goes through this gateway.
            // (currently we support use case with only 1 ethernet gateway)
            memcpy(eth->h_source, dmac, ETH_ALEN);

            // Update IP address (DESTINATION NAT)
            copy_ip_addr(&old_addr,daddr);
            copy_ip_addr(&new_addr, rsIp);
            copy_ip_addr(daddr, rsIp); // use real server IP address as destination

            // TODO #15 we should probably decrement ttl too
        }
    } else {
        // Is it egress traffic ? source ip == a real server IP
        ip_addr * rsIp = realServersMap.lookup(saddr);
        if (rsIp != NULL) {
            // do not handle traffic on ports we don't want to redirect
            if (!ports.lookup(&(udp->source))) {
                log(TRACE, ctx, EGRESS_NOT_HANDLED_PORT, &logEvent);
                return XDP_PASS;
            } else {
                // Handle egress traffic
                // Find real server associated to this foreign peer
                struct associationKey k = {};
                copy_ip_addr(&k.ipAddr, daddr);
                k.port = udp->dest;
                ip_addr * currentRsIp = associationTable.lookup(&k);
                // Create association if no real server associated
                // (or if real server associated does not exist anymore)
                if (currentRsIp == NULL ||  realServersMap.lookup(currentRsIp) == NULL ) {
                    if (associationTable.update(&k, rsIp)) {
                        log(ERROR, ctx, EGRESS_CANNOT_CREATE_ASSO, &logEvent);
                        return XDP_DROP; // XDP_ABORTED ?
                    }
                    logEvent.code = EGRESS_NEW_NAT;
                } else if (!compare_ip_addr(currentRsIp, rsIp)) {
                    // If there is an association
                    // only associated server is allow to send packet
                    log(INFO, ctx, EGRESS_NOT_AUTHORIZED, &logEvent);
                    return XDP_DROP;
                } else {
                    logEvent.code = EGRESS_REUSED_NAT;
                }
                
                // Eth address swapping
                unsigned char dmac[ETH_ALEN];
                memcpy(dmac, eth->h_dest, ETH_ALEN);             
                // Use virtual server MAC address (so packet destination) as source
                memcpy(eth->h_dest, eth->h_source, ETH_ALEN); 
                // Use source ethernet address as destination,
                // as we supose all ethernet traffic goes through this gateway.
                // (currently we support use case with only 1 ethernet gateway)
                memcpy(eth->h_source, dmac, ETH_ALEN);

                // Update IP address (SOURCE NAT)
                copy_ip_addr(&old_addr,saddr);
                copy_ip_addr(&new_addr,vsIp);
                copy_ip_addr(saddr,vsIp); // use virtual server IP address as source

                // TODO #15 we should probably decrement ttl too
            }
        } else {
            // neither ingress(destIP=VirtualServerIP) nor egress(sourceIP=RealServerIP) traffic
            log(TRACE, ctx, UNHANDLED_TRAFFIC, &logEvent);
            return XDP_PASS;
        }
    }
  
    // Update IP checksum
    update_ip_checksum(eth, data_end, old_addr, new_addr);

    // Update UDP checksum
    udp->check = update_udp_checksum(udp->check, old_addr, new_addr);

    // Log address translation
    // Store new addresses
    memcpy(&logEvent.ndmac, eth->h_dest, ETH_ALEN);
    memcpy(&logEvent.nsmac, eth->h_source, ETH_ALEN);
    copy_ip_addr(&logEvent.ndaddr, daddr);
    copy_ip_addr(&logEvent.nsaddr, saddr);
    log(DEBUG, ctx, logEvent.code, &logEvent);

    return XDP_TX;
}
