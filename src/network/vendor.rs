//! MAC Address Vendor Lookup using OUI Database
//!
//! Uses the macaddress.io database to identify device manufacturers.

use mac_oui::Oui;
use std::sync::OnceLock;

/// Global OUI database instance (loaded once)
static OUI_DB: OnceLock<Option<Oui>> = OnceLock::new();

/// Initialize the OUI database
fn get_oui_db() -> Option<&'static Oui> {
    OUI_DB.get_or_init(|| Oui::default().ok()).as_ref()
}

/// Vendor lookup result with randomization detection
pub struct VendorInfo {
    pub vendor: Option<String>,
    pub is_randomized: bool,
}

/// Check if MAC address is locally administered (randomized/virtual)
///
/// Bit 2 of the first byte indicates locally administered:
/// - 0 = Universally Administered (real hardware)
/// - 1 = Locally Administered (virtual/randomized)
pub fn is_locally_administered(mac: &str) -> bool {
    // Parse first byte from MAC string
    let normalized: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(2)
        .collect();

    if normalized.len() < 2 {
        return false;
    }

    if let Ok(first_byte) = u8::from_str_radix(&normalized, 16) {
        // Check bit 2 (0x02)
        (first_byte & 0x02) != 0
    } else {
        false
    }
}

/// Look up the vendor/manufacturer for a given MAC address
/// Returns vendor info including randomization status
pub fn lookup_vendor_info(mac: &str) -> VendorInfo {
    let is_randomized = is_locally_administered(mac);

    // If randomized, return special vendor name
    if is_randomized {
        return VendorInfo {
            vendor: Some("Private Device (Randomized MAC)".to_string()),
            is_randomized: true,
        };
    }

    // Otherwise, look up in OUI database
    let vendor = if let Some(db) = get_oui_db() {
        if let Ok(Some(entry)) = db.lookup_by_mac(mac) {
            Some(entry.company_name.clone())
        } else {
            None
        }
    } else {
        None
    };

    VendorInfo {
        vendor,
        is_randomized: false,
    }
}

/// Legacy function for backward compatibility
pub fn lookup_vendor(mac: &str) -> Option<String> {
    lookup_vendor_info(mac).vendor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locally_administered() {
        // Locally administered MACs (bit 2 set)
        assert!(is_locally_administered("5a:05:d7:51:07:81"));
        assert!(is_locally_administered("d2:81:c8:45:6b:71"));
        assert!(is_locally_administered("de:b2:52:65:8c:55"));

        // Universally administered MACs (bit 2 not set)
        assert!(!is_locally_administered("34:4a:c3:22:6f:90"));
        assert!(!is_locally_administered("00:1C:B3:00:00:00"));
    }

    #[test]
    fn test_lookup_vendor() {
        let result = lookup_vendor("00:1C:B3:00:00:00");
        println!("Vendor lookup result: {:?}", result);
    }
}
