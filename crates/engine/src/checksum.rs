//! Internet checksum (RFC 1071) and incremental update (RFC 1624).
//!
//! Only the changed fields are recomputed per packet; the whole packet is never
//! rescanned. This is what keeps CPU load flat at high throughput.

/// Adds `data` to the sum as 16-bit big-endian words.
pub fn add(mut acc: u32, data: &[u8]) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        acc += u32::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
        acc += u32::from(*last) << 8;
    }
    acc
}

/// Folds the sum and takes its ones' complement.
pub fn finish(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// Updates the checksum when a field changes from `old` -> `new`:
/// `HC' = ~(~HC + ~m + m')` (RFC 1624, eqn. 3). Lengths must be equal and even.
pub fn update(check: u16, old: &[u8], new: &[u8]) -> u16 {
    debug_assert_eq!(old.len(), new.len());
    debug_assert_eq!(old.len() % 2, 0);
    let mut acc = u32::from(!check);
    for (o, n) in old.as_chunks::<2>().0.iter().zip(new.as_chunks::<2>().0) {
        acc += u32::from(!u16::from_be_bytes(*o));
        acc += u32::from(u16::from_be_bytes(*n));
    }
    finish(acc)
}

/// Sum of the IPv4 pseudo-header for TCP/UDP.
pub fn pseudo_v4(src: [u8; 4], dst: [u8; 4], protocol: u8, len: u16) -> u32 {
    let acc = add(add(0, &src), &dst);
    acc + u32::from(protocol) + u32::from(len)
}

/// Sum of the IPv6 pseudo-header for TCP/UDP (RFC 8200 section 8.1).
pub fn pseudo_v6(src: [u8; 16], dst: [u8; 16], next_header: u8, len: u32) -> u32 {
    let acc = add(add(0, &src), &dst);
    acc + (len >> 16) + (len & 0xffff) + u32::from(next_header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example() {
        // Example from RFC 1071 section 3: sum 0xddf2, checksum ~0xddf2.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(finish(add(0, &data)), !0xddf2);
    }

    #[test]
    fn incremental_matches_full() {
        let mut data: Vec<u8> = (0u8..64).map(|b| b.wrapping_mul(37)).collect();
        let before = finish(add(0, &data));
        let old = [data[10], data[11], data[12], data[13]];
        let new = [0xc6, 0x12, 0x00, 0x01];
        data[10..14].copy_from_slice(&new);
        assert_eq!(update(before, &old, &new), finish(add(0, &data)));
    }
}
