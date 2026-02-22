//! LAN-only ICE candidate filter.
//!
//! Accepts only candidates whose connection-address is a private or
//! link-local IP. Rejects public IPs and unresolvable mDNS (.local) hostnames.
//!
//! Reference: TRANSPORT_CONTRACT.md §5 (LAN-Only Mode).

use std::net::IpAddr;

/// Returns `true` if the candidate should be kept (LAN-only policy).
///
/// ICE candidate attribute format (RFC 8445 §5.1):
///   candidate:<foundation> <component> <transport> <priority> <connection-address> <port> ...
///
/// The connection-address is at token index 4 (0-based) of the `candidate:` attribute value.
/// If the candidate string starts with "candidate:", that prefix is part of token 0.
pub fn is_lan_candidate(candidate_str: &str) -> bool {
    // Empty or end-of-candidates marker
    let trimmed = candidate_str.trim();
    if trimmed.is_empty() {
        return false;
    }

    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    // Need at least 5 tokens: foundation, component, transport, priority, address
    if tokens.len() < 5 {
        return false;
    }

    let addr_str = tokens[4];

    // Reject mDNS (.local) candidates — cannot verify they resolve to LAN
    if addr_str.ends_with(".local") {
        return false;
    }

    match addr_str.parse::<IpAddr>() {
        Ok(ip) => is_private_or_link_local(&ip),
        // Not a valid IP and not mDNS → reject
        Err(_) => false,
    }
}

/// Returns `true` if the IP is private (RFC 1918 / RFC 4193) or link-local.
fn is_private_or_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 169.254.0.0/16 (link-local)
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // 127.0.0.0/8 (loopback — accept for local testing)
            if octets[0] == 127 {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // fe80::/10 (link-local)
            if segments[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            // fc00::/7 (unique local — covers fc00::/8 and fd00::/8)
            if segments[0] & 0xfe00 == 0xfc00 {
                return true;
            }
            // ::1 (loopback)
            if v6.is_loopback() {
                return true;
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Private/link-local IPv4 — ACCEPT ──────────────────────

    #[test]
    fn accept_10_network() {
        let c = "candidate:1 1 UDP 2130706431 10.0.0.1 12345 typ host";
        assert!(is_lan_candidate(c), "10.0.0.0/8 must be accepted");
    }

    #[test]
    fn accept_172_16_network() {
        let c = "candidate:1 1 UDP 2130706431 172.16.0.1 12345 typ host";
        assert!(is_lan_candidate(c), "172.16.0.0/12 must be accepted");
    }

    #[test]
    fn accept_172_31_network() {
        let c = "candidate:1 1 UDP 2130706431 172.31.255.255 12345 typ host";
        assert!(is_lan_candidate(c), "172.31.x.x must be accepted");
    }

    #[test]
    fn accept_192_168_network() {
        let c = "candidate:1 1 UDP 2130706431 192.168.1.100 12345 typ host";
        assert!(is_lan_candidate(c), "192.168.0.0/16 must be accepted");
    }

    #[test]
    fn accept_link_local_ipv4() {
        let c = "candidate:1 1 UDP 2130706431 169.254.1.1 12345 typ host";
        assert!(is_lan_candidate(c), "169.254.0.0/16 must be accepted");
    }

    #[test]
    fn accept_loopback_ipv4() {
        let c = "candidate:1 1 UDP 2130706431 127.0.0.1 12345 typ host";
        assert!(is_lan_candidate(c), "127.0.0.1 must be accepted");
    }

    // ── Private/link-local IPv6 — ACCEPT ──────────────────────

    #[test]
    fn accept_link_local_ipv6() {
        let c = "candidate:1 1 UDP 2130706431 fe80::1 12345 typ host";
        assert!(is_lan_candidate(c), "fe80::/10 must be accepted");
    }

    #[test]
    fn accept_unique_local_ipv6() {
        let c = "candidate:1 1 UDP 2130706431 fd00::1 12345 typ host";
        assert!(is_lan_candidate(c), "fd00::/8 must be accepted");
    }

    // ── Public IPs — REJECT ───────────────────────────────────

    #[test]
    fn reject_public_ipv4() {
        let c = "candidate:1 1 UDP 2130706431 203.0.113.5 12345 typ srflx";
        assert!(!is_lan_candidate(c), "public IPv4 must be rejected");
    }

    #[test]
    fn reject_public_ipv6() {
        let c = "candidate:1 1 UDP 2130706431 2001:db8::1 12345 typ srflx";
        assert!(!is_lan_candidate(c), "public IPv6 must be rejected");
    }

    #[test]
    fn reject_172_15_not_private() {
        let c = "candidate:1 1 UDP 2130706431 172.15.0.1 12345 typ host";
        assert!(!is_lan_candidate(c), "172.15.x.x is not RFC1918");
    }

    #[test]
    fn reject_172_32_not_private() {
        let c = "candidate:1 1 UDP 2130706431 172.32.0.1 12345 typ host";
        assert!(!is_lan_candidate(c), "172.32.x.x is not RFC1918");
    }

    // ── mDNS — REJECT ─────────────────────────────────────────

    #[test]
    fn reject_mdns_candidate() {
        let c = "candidate:1 1 UDP 2130706431 abc123.local 12345 typ host";
        assert!(!is_lan_candidate(c), "mDNS .local must be rejected");
    }

    // ── Malformed — REJECT ────────────────────────────────────

    #[test]
    fn reject_empty() {
        assert!(!is_lan_candidate(""), "empty must be rejected");
    }

    #[test]
    fn reject_too_short() {
        assert!(
            !is_lan_candidate("candidate:1 1 UDP"),
            "too few tokens must be rejected"
        );
    }

    #[test]
    fn reject_garbage_address() {
        let c = "candidate:1 1 UDP 2130706431 notanip 12345 typ host";
        assert!(!is_lan_candidate(c), "non-IP must be rejected");
    }
}
