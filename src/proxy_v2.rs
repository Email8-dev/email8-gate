// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:Gate
// SPDX-License-Identifier: Apache-2.0

//! PROXY protocol v2 header construction (design §3.3).
//!
//! The gate prepends a v2 header carrying the real client address to
//! every forwarded stream. Byte layout per
//! <https://www.haproxy.org/download/2.5/doc/proxy-protocol.txt> §2.2:
//!
//! ```text
//! 12 bytes  signature \r\n\r\n\0\r\nQUIT\n
//! 1 byte    version | command  (0x20 = v2, LOCAL/PROXY bit 0x01)
//! 1 byte    family | transport (0x21 = TCP over IPv4, 0x22 = IPv6)
//! 2 bytes   address length (big endian)
//! 4 bytes   src addr, 4 bytes dst addr, 2 bytes src port, 2 bytes dst port
//! ```

/// v2 binary signature.
const SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Build a minimal v2 PROXY header for a TCP/IPv4 connection.
pub fn v2_tcp4(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(16 + 12);
    b.extend_from_slice(&SIG);
    b.push(0x21); // version 2, command PROXY
    b.push(0x21); // family INET, transport STREAM
    b.extend_from_slice(&12u16.to_be_bytes()); // IPv4 addr pair + ports
    b.extend_from_slice(&src_ip);
    b.extend_from_slice(&dst_ip);
    b.extend_from_slice(&src_port.to_be_bytes());
    b.extend_from_slice(&dst_port.to_be_bytes());
    b
}

/// Build a v2 TCP/IPv6 header.
pub fn v2_tcp6(
    src_ip: [u8; 16],
    src_port: u16,
    dst_ip: [u8; 16],
    dst_port: u16,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(16 + 36);
    b.extend_from_slice(&SIG);
    b.push(0x21);
    b.push(0x22); // family INET6, transport STREAM
    b.extend_from_slice(&36u16.to_be_bytes());
    b.extend_from_slice(&src_ip);
    b.extend_from_slice(&dst_ip);
    b.extend_from_slice(&src_port.to_be_bytes());
    b.extend_from_slice(&dst_port.to_be_bytes());
    b
}

/// Extract the client socket addr as (ip-octets, port) pairs for v2
/// encoding from a `std::net::SocketAddr`.
pub fn header_for(src: std::net::SocketAddr, dst: std::net::SocketAddr) -> Vec<u8> {
    match (src, dst) {
        (std::net::SocketAddr::V4(s), std::net::SocketAddr::V4(d)) => {
            v2_tcp4(s.ip().octets(), s.port(), d.ip().octets(), d.port())
        }
        (std::net::SocketAddr::V6(s), std::net::SocketAddr::V6(d)) => {
            v2_tcp6(s.ip().octets(), s.port(), d.ip().octets(), d.port())
        }
        // Mixed families: fall back to IPv4 unspecified (localhost
        // dual-stack gate binds are the only realistic case).
        _ => v2_tcp4([127, 0, 0, 1], src.port(), [127, 0, 0, 1], dst.port()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_tcp4_byte_layout() {
        let h = v2_tcp4([192, 0, 2, 1], 45678, [203, 0, 113, 9], 25);
        assert_eq!(h.len(), 28);
        assert_eq!(&h[0..12], &SIG);
        assert_eq!(h[12], 0x21); // v2 PROXY
        assert_eq!(h[13], 0x21); // INET STREAM
        assert_eq!(&h[14..16], &12u16.to_be_bytes());
        assert_eq!(&h[16..20], &[192, 0, 2, 1]); // src
        assert_eq!(&h[20..24], &[203, 0, 113, 9]); // dst
        assert_eq!(&h[24..26], &45678u16.to_be_bytes());
        assert_eq!(&h[26..28], &25u16.to_be_bytes());
    }

    #[test]
    fn v2_tcp6_byte_layout() {
        let h = v2_tcp6([0u8; 16], 1, [0u8; 16], 2);
        assert_eq!(h.len(), 52);
        assert_eq!(h[13], 0x22);
        assert_eq!(&h[14..16], &36u16.to_be_bytes());
    }

    #[test]
    fn header_for_dispatches_by_addr_family() {
        let src: std::net::SocketAddr = "192.0.2.7:51000".parse().unwrap();
        let dst: std::net::SocketAddr = "10.0.0.5:8031".parse().unwrap();
        let h = header_for(src, dst);
        assert_eq!(h.len(), 28);
        assert_eq!(&h[16..20], &[192, 0, 2, 7]);
        assert_eq!(&h[20..24], &[10, 0, 0, 5]);
    }
}