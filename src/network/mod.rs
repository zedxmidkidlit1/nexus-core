//! Network module - interface detection, subnet utilities, DNS resolution, device inference

mod device;
mod dns;
mod interface;
mod subnet;
mod vendor;

pub use device::{calculate_risk_score, infer_device_type, DeviceType};
pub use dns::dns_scan;
pub use interface::{find_valid_interface, interface_score, list_valid_interfaces};
pub use subnet::{calculate_subnet_ips, is_local_subnet, is_special_address};
pub use vendor::{lookup_vendor, lookup_vendor_info};
