pub fn is_reverse_zone(name: &str) -> bool {
    let n = name.trim_end_matches('.');
    n.ends_with(".in-addr.arpa") || n == "in-addr.arpa"
        || n.ends_with(".ip6.arpa") || n == "ip6.arpa"
}

/// "1.2.3.4" → "4.3.2.1.in-addr.arpa."
pub fn ip_to_arpa(ip: &str) -> Option<String> {
    if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
        let o = addr.octets();
        return Some(format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0]));
    }
    if let Ok(addr) = ip.parse::<std::net::Ipv6Addr>() {
        let bytes = addr.octets();
        let nibbles: Vec<String> = bytes
            .iter()
            .flat_map(|b| [b >> 4, b & 0x0f])
            .rev()
            .map(|n| format!("{n:x}"))
            .collect();
        return Some(format!("{}.ip6.arpa.", nibbles.join(".")));
    }
    None
}

/// "1.168.192.in-addr.arpa." → "192.168.1.0/24"
pub fn arpa_to_network(zone: &str) -> Option<String> {
    let z = zone.trim_end_matches('.');
    if let Some(rest) = z.strip_suffix(".in-addr.arpa") {
        let parts: Vec<&str> = rest.split('.').collect();
        let prefix_len = parts.len() * 8;
        let mut octets = ["0", "0", "0", "0"];
        for (i, p) in parts.iter().rev().enumerate() {
            if i < 4 {
                octets[i] = p;
            }
        }
        return Some(format!("{}/{}", octets.join("."), prefix_len));
    }
    if let Some(rest) = z.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = rest.split('.').collect();
        let prefix_len = nibbles.len() * 4;
        let mut all = vec!["0"; 32];
        for (i, n) in nibbles.iter().rev().enumerate() {
            if i < 32 {
                all[i] = n;
            }
        }
        let segments: Vec<String> = all.chunks(4).map(|c| c.join("")).collect();
        return Some(format!("{}/{}", segments.join(":"), prefix_len));
    }
    None
}

/// "192.168.1.0/24" → "1.168.192.in-addr.arpa."
pub fn network_to_arpa(network: &str) -> Option<String> {
    let (ip, prefix_str) = network.split_once('/')?;
    let prefix: u32 = prefix_str.parse().ok()?;

    if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
        if prefix > 32 {
            return None;
        }
        let octs = addr.octets();
        let significant = prefix.div_ceil(8) as usize;
        let reversed: Vec<String> = octs[..significant].iter().rev().map(|o| o.to_string()).collect();
        return Some(format!("{}.in-addr.arpa.", reversed.join(".")));
    }
    if let Ok(addr) = ip.parse::<std::net::Ipv6Addr>() {
        if prefix > 128 {
            return None;
        }
        let bytes = addr.octets();
        let all_nibbles: Vec<u8> = bytes.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect();
        let nibble_count = prefix.div_ceil(4) as usize;
        let reversed: Vec<String> = all_nibbles[..nibble_count]
            .iter()
            .rev()
            .map(|n| format!("{n:x}"))
            .collect();
        return Some(format!("{}.ip6.arpa.", reversed.join(".")));
    }
    None
}

/// Full PTR record name for an IP address.
pub fn ptr_record_name(ip: &str) -> Option<String> {
    ip_to_arpa(ip)
}

/// Candidate reverse zones for an IP (from most to least specific).
pub fn reverse_zone_candidates(ip: &str) -> Vec<String> {
    if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
        let o = addr.octets();
        return vec![
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0]),
            format!("{}.{}.{}.in-addr.arpa.", o[2], o[1], o[0]),
            format!("{}.{}.in-addr.arpa.", o[1], o[0]),
            format!("{}.in-addr.arpa.", o[0]),
        ];
    }
    if let Ok(addr) = ip.parse::<std::net::Ipv6Addr>() {
        let bytes = addr.octets();
        let nibbles: Vec<u8> = bytes
            .iter()
            .flat_map(|b| [b >> 4, b & 0x0f])
            .collect();
        let mut candidates = Vec::new();
        for len in (1..=32).rev() {
            let reversed: Vec<String> = nibbles[..len].iter().rev().map(|n| format!("{n:x}")).collect();
            candidates.push(format!("{}.ip6.arpa.", reversed.join(".")));
        }
        return candidates;
    }
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_reverse_zone() {
        assert!(is_reverse_zone("1.168.192.in-addr.arpa."));
        assert!(is_reverse_zone("1.0.0.0.ip6.arpa."));
        assert!(!is_reverse_zone("example.com."));
    }

    #[test]
    fn test_ip_to_arpa_v4() {
        assert_eq!(ip_to_arpa("1.2.3.4").unwrap(), "4.3.2.1.in-addr.arpa.");
    }

    #[test]
    fn test_network_to_arpa_v4() {
        assert_eq!(network_to_arpa("192.168.1.0/24").unwrap(), "1.168.192.in-addr.arpa.");
        assert_eq!(network_to_arpa("10.0.0.0/8").unwrap(), "10.in-addr.arpa.");
    }

    #[test]
    fn test_arpa_to_network_v4() {
        assert_eq!(arpa_to_network("1.168.192.in-addr.arpa.").unwrap(), "192.168.1.0/24");
    }

    #[test]
    fn test_ip_to_arpa_v6() {
        assert_eq!(
            ip_to_arpa("2001:db8::1").unwrap(),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
    }

    #[test]
    fn test_reverse_zone_candidates_v6() {
        let candidates = reverse_zone_candidates("2001:db8::10");
        assert!(candidates.contains(&"8.b.d.0.1.0.0.2.ip6.arpa.".to_string()));
    }
}
