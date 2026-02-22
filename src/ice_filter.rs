//! ICE candidate filter with network scope policy.
//!
//! LAN mode: accept only private/link-local IPs (RFC 1918, RFC 4193, loopback).
//! Overlay mode: LAN + CGNAT 100.64.0.0/10 (e.g. Tailscale).
//! Global mode: accept all valid IPs (private + public + CGNAT).
//! All modes reject mDNS (.local) and malformed candidates.
//!
//! Reference: TRANSPORT_CONTRACT.md §5 (LAN-Only Mode).

use std::net::IpAddr;

/// Network scope policy for ICE candidate filtering.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NetworkScope {
    /// LocalBolt: only private/link-local/loopback IPs.
    Lan,
    /// LocalBolt over Tailscale: LAN + CGNAT 100.64.0.0/10.
    Overlay,
    /// ByteBolt: all valid IPs including public and CGNAT.
    Global,
}

/// Returns `true` if the candidate is allowed under the given network scope policy.
///
/// ICE candidate attribute format (RFC 8445 §5.1):
///   candidate:<foundation> <component> <transport> <priority> <connection-address> <port> ...
///
/// The connection-address is at token index 4 (0-based) of the `candidate:` attribute value.
/// If the candidate string starts with "candidate:", that prefix is part of token 0.
pub fn is_allowed_candidate(candidate_str: &str, scope: NetworkScope) -> bool {
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
        Ok(ip) => match scope {
            NetworkScope::Lan => is_private_or_link_local(&ip),
            NetworkScope::Overlay => is_private_or_link_local(&ip) || is_cgnat(&ip),
            NetworkScope::Global => true,
        },
        // Not a valid IP and not mDNS → reject
        Err(_) => false,
    }
}

/// Backward-compatible wrapper: LAN-only policy.
/// Used by existing tests to verify LAN behavior is preserved.
#[cfg(test)]
pub fn is_lan_candidate(candidate_str: &str) -> bool {
    is_allowed_candidate(candidate_str, NetworkScope::Lan)
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

/// Returns `true` if the IP is in the CGNAT range 100.64.0.0/10.
fn is_cgnat(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 100.64.0.0/10: first octet 100, second octet 64..127
            octets[0] == 100 && (64..=127).contains(&octets[1])
        }
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Private/link-local IPv4 — ACCEPT (both scopes) ───────

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

    // ── Public IPs — REJECT in LAN ───────────────────────────

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

    // ── mDNS — REJECT (both scopes) ──────────────────────────

    #[test]
    fn reject_mdns_candidate() {
        let c = "candidate:1 1 UDP 2130706431 abc123.local 12345 typ host";
        assert!(!is_lan_candidate(c), "mDNS .local must be rejected");
    }

    // ── Malformed — REJECT (both scopes) ─────────────────────

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

    // ── Global scope — ACCEPT public IPs ─────────────────────

    #[test]
    fn global_accepts_public_ipv4() {
        let c = "candidate:1 1 UDP 2130706431 203.0.113.5 12345 typ srflx";
        assert!(
            is_allowed_candidate(c, NetworkScope::Global),
            "global must accept public IPv4"
        );
    }

    #[test]
    fn global_accepts_public_ipv6() {
        let c = "candidate:1 1 UDP 2130706431 2001:db8::1 12345 typ srflx";
        assert!(
            is_allowed_candidate(c, NetworkScope::Global),
            "global must accept public IPv6"
        );
    }

    #[test]
    fn lan_rejects_public_ipv4() {
        let c = "candidate:1 1 UDP 2130706431 203.0.113.5 12345 typ srflx";
        assert!(
            !is_allowed_candidate(c, NetworkScope::Lan),
            "lan must reject public IPv4"
        );
    }

    #[test]
    fn lan_rejects_public_ipv6() {
        let c = "candidate:1 1 UDP 2130706431 2001:db8::1 12345 typ srflx";
        assert!(
            !is_allowed_candidate(c, NetworkScope::Lan),
            "lan must reject public IPv6"
        );
    }

    // ── CGNAT — Global accepts, LAN rejects ──────────────────

    #[test]
    fn global_accepts_cgnat_100_64_range() {
        let c = "candidate:1 1 UDP 2130706431 100.64.0.1 12345 typ host";
        assert!(
            is_allowed_candidate(c, NetworkScope::Global),
            "global must accept CGNAT 100.64/10"
        );
    }

    #[test]
    fn lan_rejects_cgnat_100_64_range() {
        let c = "candidate:1 1 UDP 2130706431 100.64.0.1 12345 typ host";
        assert!(
            !is_allowed_candidate(c, NetworkScope::Lan),
            "lan must reject CGNAT 100.64/10"
        );
    }

    // ── Global still rejects malformed/mDNS ──────────────────

    #[test]
    fn global_rejects_mdns() {
        let c = "candidate:1 1 UDP 2130706431 abc123.local 12345 typ host";
        assert!(
            !is_allowed_candidate(c, NetworkScope::Global),
            "global must still reject mDNS"
        );
    }

    #[test]
    fn global_rejects_empty() {
        assert!(
            !is_allowed_candidate("", NetworkScope::Global),
            "global must reject empty"
        );
    }

    #[test]
    fn global_rejects_garbage() {
        let c = "candidate:1 1 UDP 2130706431 notanip 12345 typ host";
        assert!(
            !is_allowed_candidate(c, NetworkScope::Global),
            "global must reject non-IP"
        );
    }

    // ── Global accepts private IPs too (superset) ────────────

    #[test]
    fn global_accepts_private_ipv4() {
        let c = "candidate:1 1 UDP 2130706431 192.168.1.1 12345 typ host";
        assert!(
            is_allowed_candidate(c, NetworkScope::Global),
            "global must accept private IPv4 (superset)"
        );
    }

    // ── Overlay scope — LAN + CGNAT 100.64/10 ────────────────

    #[test]
    fn overlay_accepts_cgnat_10064_ipv4() {
        let c = "candidate:1 1 UDP 2130706431 100.74.48.28 12345 typ host";
        assert!(
            is_allowed_candidate(c, NetworkScope::Overlay),
            "overlay must accept CGNAT 100.64/10 (Tailscale)"
        );
    }

    #[test]
    fn overlay_accepts_private_ipv4() {
        let c = "candidate:1 1 UDP 2130706431 192.168.1.1 12345 typ host";
        assert!(
            is_allowed_candidate(c, NetworkScope::Overlay),
            "overlay must accept private IPv4 (superset of LAN)"
        );
    }

    #[test]
    fn overlay_rejects_public_ipv4() {
        let c = "candidate:1 1 UDP 2130706431 203.0.113.5 12345 typ srflx";
        assert!(
            !is_allowed_candidate(c, NetworkScope::Overlay),
            "overlay must reject public IPv4"
        );
    }

    #[test]
    fn overlay_rejects_mdns() {
        let c = "candidate:1 1 UDP 2130706431 abc123.local 12345 typ host";
        assert!(
            !is_allowed_candidate(c, NetworkScope::Overlay),
            "overlay must reject mDNS"
        );
    }

    #[test]
    fn overlay_accepts_cgnat_boundary_low() {
        let c = "candidate:1 1 UDP 2130706431 100.64.0.1 12345 typ host";
        assert!(
            is_allowed_candidate(c, NetworkScope::Overlay),
            "overlay must accept 100.64.0.1 (low boundary)"
        );
    }

    #[test]
    fn overlay_accepts_cgnat_boundary_high() {
        let c = "candidate:1 1 UDP 2130706431 100.127.255.254 12345 typ host";
        assert!(
            is_allowed_candidate(c, NetworkScope::Overlay),
            "overlay must accept 100.127.255.254 (high boundary)"
        );
    }

    #[test]
    fn overlay_rejects_outside_cgnat() {
        let c = "candidate:1 1 UDP 2130706431 100.128.0.1 12345 typ host";
        assert!(
            !is_allowed_candidate(c, NetworkScope::Overlay),
            "overlay must reject 100.128.0.1 (outside 100.64/10)"
        );
    }
}
