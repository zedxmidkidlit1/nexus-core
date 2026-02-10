//! Tests for subnet calculation and utilities

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::models::InterfaceInfo;
    use ipnetwork::Ipv4Network;
    use pnet::datalink::NetworkInterface;
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    fn create_test_interface(ip: &str, prefix_len: u8) -> InterfaceInfo {
        InterfaceInfo {
            name: "eth0".to_string(),
            ip: ip.parse().unwrap(),
            mac: MacAddr::zero(),
            prefix_len,
            pnet_interface: NetworkInterface {
                name: "eth0".to_string(),
                description: "Test interface".to_string(),
                index: 0,
                mac: None,
                ips: vec![],
                flags: 0,
            },
        }
    }

    #[test]
    fn test_is_special_address_network() {
        let subnet: Ipv4Network = "192.168.1.0/24".parse().unwrap();
        let network_addr: Ipv4Addr = "192.168.1.0".parse().unwrap();

        assert!(is_special_address(network_addr, &subnet));
    }

    #[test]
    fn test_is_special_address_broadcast() {
        let subnet: Ipv4Network = "192.168.1.0/24".parse().unwrap();
        let broadcast_addr: Ipv4Addr = "192.168.1.255".parse().unwrap();

        assert!(is_special_address(broadcast_addr, &subnet));
    }

    #[test]
    fn test_is_special_address_regular_ip() {
        let subnet: Ipv4Network = "192.168.1.0/24".parse().unwrap();
        let regular: Ipv4Addr = "192.168.1.100".parse().unwrap();

        assert!(!is_special_address(regular, &subnet));
    }

    #[test]
    fn test_is_local_subnet_same_subnet() {
        let interface = create_test_interface("192.168.1.10", 24);
        let target: Ipv4Addr = "192.168.1.50".parse().unwrap();

        assert!(is_local_subnet(target, &interface));
    }

    #[test]
    fn test_is_local_subnet_different_subnet() {
        let interface = create_test_interface("192.168.1.10", 24);
        let target: Ipv4Addr = "192.168.2.50".parse().unwrap();

        assert!(!is_local_subnet(target, &interface));
    }

    #[test]
    fn test_calculate_subnet_ips_class_c() {
        let interface = create_test_interface("192.168.1.10", 24);

        let result = calculate_subnet_ips(&interface);
        assert!(result.is_ok());

        let (subnet, ips) = result.unwrap();
        assert_eq!(subnet.prefix(), 24);
        assert_eq!(ips.len(), 254); // 256 - 2 (network + broadcast)

        // Should not contain network or broadcast
        assert!(!ips.contains(&"192.168.1.0".parse().unwrap()));
        assert!(!ips.contains(&"192.168.1.255".parse().unwrap()));

        // Should contain valid IPs
        assert!(ips.contains(&"192.168.1.1".parse().unwrap()));
        assert!(ips.contains(&"192.168.1.254".parse().unwrap()));
    }

    #[test]
    fn test_calculate_subnet_ips_small_subnet() {
        let interface = create_test_interface("192.168.1.10", 30);

        let result = calculate_subnet_ips(&interface);
        assert!(result.is_ok());

        let (_, ips) = result.unwrap();
        assert_eq!(ips.len(), 2); // 4 - 2 (network + broadcast)
    }
}
