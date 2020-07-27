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
