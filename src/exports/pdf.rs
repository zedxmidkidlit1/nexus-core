//! PDF export functionality
//!
//! Generate professional PDF reports using printpdf

use crate::database::NetworkStats;
use crate::insights::SecurityReport;
use crate::models::{HostInfo, ScanResult};
use anyhow::Result;
use chrono::Utc;
use printpdf::*;
use std::io::BufWriter;

const FONT_SIZE_TITLE: f32 = 24.0;
const FONT_SIZE_HEADING: f32 = 16.0;
const FONT_SIZE_SUBHEADING: f32 = 12.0;
const FONT_SIZE_BODY: f32 = 10.0;
const DEVICE_COL_IP_X: f32 = 20.0;
const DEVICE_COL_HOSTNAME_X: f32 = 60.0;
const DEVICE_COL_TYPE_X: f32 = 100.0;
const DEVICE_COL_RISK_X: f32 = 150.0;

/// Generate a scan report PDF
pub fn generate_scan_report_pdf(
    scan: &ScanResult,
    devices: &[HostInfo],
    stats: Option<&NetworkStats>,
) -> Result<Vec<u8>> {
    let (doc, page1, layer1) =
        PdfDocument::new("Network Scan Report", Mm(210.0), Mm(297.0), "Layer 1");

    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;

    let mut current_layer = doc.get_page(page1).get_layer(layer1);

    let mut y_pos = 270.0; // Start from top

    // === COVER PAGE ===
    // Title
    current_layer.use_text(
        "Network Scan Report",
        FONT_SIZE_TITLE,
        Mm(20.0),
        Mm(y_pos),
        &font_bold,
    );
    y_pos -= 15.0;

    // Date
    let scan_date = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    current_layer.use_text(
        format!("Generated: {}", scan_date),
        FONT_SIZE_BODY,
        Mm(20.0),
        Mm(y_pos),
        &font,
    );
    y_pos -= 10.0;

    // Scan details
    current_layer.use_text(
        format!("Scanned Subnet: {}", scan.subnet),
        FONT_SIZE_BODY,
        Mm(20.0),
        Mm(y_pos),
        &font,
    );
    y_pos -= 7.0;

    current_layer.use_text(
        format!("Total Devices Found: {}", scan.active_hosts.len()),
        FONT_SIZE_BODY,
        Mm(20.0),
        Mm(y_pos),
        &font,
    );
    y_pos -= 7.0;

    current_layer.use_text(
        format!(
            "Scan Duration: {:.2}s",
            scan.scan_duration_ms as f64 / 1000.0
        ),
        FONT_SIZE_BODY,
        Mm(20.0),
        Mm(y_pos),
        &font,
    );
    y_pos -= 20.0;

    // === EXECUTIVE SUMMARY ===
    draw_section_header(&current_layer, &font_bold, "Executive Summary", &mut y_pos);

    let high_risk_count = devices.iter().filter(|d| d.risk_score >= 50).count();
    let low_latency_count = devices
        .iter()
        .filter(|d| d.response_time_ms.unwrap_or(999) < 10)
        .count();

    current_layer.use_text(
        format!("• High-risk devices: {}", high_risk_count),
        FONT_SIZE_BODY,
        Mm(20.0),
        Mm(y_pos),
        &font,
    );
    y_pos -= 7.0;

    current_layer.use_text(
        format!("• Low-latency devices: {}", low_latency_count),
        FONT_SIZE_BODY,
        Mm(20.0),
        Mm(y_pos),
        &font,
    );
    y_pos -= 7.0;

    if let Some(stats) = stats {
        current_layer.use_text(
            format!("• Total known devices: {}", stats.total_devices),
            FONT_SIZE_BODY,
            Mm(20.0),
            Mm(y_pos),
            &font,
        );
        y_pos -= 7.0;

        current_layer.use_text(
            format!("• New devices detected: {}", stats.new_devices_24h),
            FONT_SIZE_BODY,
            Mm(20.0),
            Mm(y_pos),
            &font,
        );
        y_pos -= 15.0;
    }

    // === DEVICE INVENTORY ===
    draw_section_header(&current_layer, &font_bold, "Device Inventory", &mut y_pos);
    draw_device_table_header(&current_layer, &font_bold, &mut y_pos);

    // Device rows (fully paginated)
    for device in devices {
        if y_pos < 20.0 {
            let (next_page, next_layer) =
                doc.add_page(Mm(210.0), Mm(297.0), "Device Inventory Continued");
            current_layer = doc.get_page(next_page).get_layer(next_layer);
            y_pos = 270.0;

            draw_section_header(
                &current_layer,
                &font_bold,
                "Device Inventory (continued)",
                &mut y_pos,
            );
            draw_device_table_header(&current_layer, &font_bold, &mut y_pos);
        }

        current_layer.use_text(
            device.ip.to_string(),
            FONT_SIZE_BODY,
            Mm(DEVICE_COL_IP_X),
            Mm(y_pos),
            &font,
        );

        let hostname = device.hostname.as_deref().unwrap_or("N/A");
        current_layer.use_text(hostname, FONT_SIZE_BODY, Mm(DEVICE_COL_HOSTNAME_X), Mm(y_pos), &font);

        current_layer.use_text(
            &device.device_type,
            FONT_SIZE_BODY,
            Mm(DEVICE_COL_TYPE_X),
            Mm(y_pos),
            &font,
        );

        current_layer.use_text(
            device.risk_score.to_string(),
            FONT_SIZE_BODY,
            Mm(DEVICE_COL_RISK_X),
            Mm(y_pos),
            &font,
        );

        y_pos -= 6.0;
    }

    // Save to bytes
    let mut buf = BufWriter::new(Vec::new());
    doc.save(&mut buf)?;
    let bytes = buf.into_inner()?;

    Ok(bytes)
}

/// Generate a network health PDF report
pub fn generate_network_health_pdf(recommendations: &SecurityReport) -> Result<Vec<u8>> {
    let (doc, page1, layer1) =
        PdfDocument::new("Network Health Report", Mm(210.0), Mm(297.0), "Layer 1");

    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;

    let mut current_layer = doc.get_page(page1).get_layer(layer1);

    let mut y_pos = 270.0;

    // Title
    current_layer.use_text(
        "Network Security Report",
        FONT_SIZE_TITLE,
        Mm(20.0),
        Mm(y_pos),
        &font_bold,
    );
    y_pos -= 15.0;

    // Date
    let report_date = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    current_layer.use_text(
        format!("Generated: {}", report_date),
        FONT_SIZE_BODY,
        Mm(20.0),
        Mm(y_pos),
        &font,
    );
    y_pos -= 15.0;

    // Summary
    draw_section_header(
        &current_layer,
        &font_bold,
        &recommendations.summary,
        &mut y_pos,
    );
    y_pos -= 5.0;

    current_layer.use_text(
        format!("Critical Issues: {}", recommendations.critical_count),
        FONT_SIZE_BODY,
        Mm(20.0),
        Mm(y_pos),
        &font,
    );
    y_pos -= 7.0;

    current_layer.use_text(
        format!("High Priority: {}", recommendations.high_count),
        FONT_SIZE_BODY,
        Mm(20.0),
        Mm(y_pos),
        &font,
    );
    y_pos -= 7.0;

    current_layer.use_text(
        format!("Total Recommendations: {}", recommendations.total_issues),
        FONT_SIZE_BODY,
        Mm(20.0),
        Mm(y_pos),
        &font,
    );
    y_pos -= 15.0;

    // Recommendations
    draw_section_header(
        &current_layer,
        &font_bold,
        "Security Recommendations",
        &mut y_pos,
    );

    for rec in recommendations.recommendations.iter() {
        if y_pos < 35.0 {
            let (next_page, next_layer) =
                doc.add_page(Mm(210.0), Mm(297.0), "Recommendations Continued");
            current_layer = doc.get_page(next_page).get_layer(next_layer);
            y_pos = 270.0;
            draw_section_header(
                &current_layer,
                &font_bold,
                "Security Recommendations (continued)",
                &mut y_pos,
            );
        }

        // Priority badge
        let priority_text = format!("[{}] {}", rec.priority.as_str(), rec.title);
        current_layer.use_text(
            &priority_text,
            FONT_SIZE_SUBHEADING,
            Mm(20.0),
            Mm(y_pos),
            &font_bold,
        );
        y_pos -= 7.0;

        // Description
        current_layer.use_text(&rec.description, FONT_SIZE_BODY, Mm(25.0), Mm(y_pos), &font);
        y_pos -= 7.0;

        // Affected devices (limit to 3)
        if !rec.affected_devices.is_empty() {
            let devices_text = if rec.affected_devices.len() <= 3 {
                format!("Affected: {}", rec.affected_devices.join(", "))
            } else {
                format!(
                    "Affected: {} (and {} more)",
                    rec.affected_devices[..3].join(", "),
                    rec.affected_devices.len() - 3
                )
            };
            current_layer.use_text(&devices_text, FONT_SIZE_BODY, Mm(25.0), Mm(y_pos), &font);
            y_pos -= 10.0;
        } else {
            y_pos -= 5.0;
        }
    }

    // Save to bytes
    let mut buf = BufWriter::new(Vec::new());
    doc.save(&mut buf)?;
    let bytes = buf.into_inner()?;

    Ok(bytes)
}

/// Helper: Draw section header
fn draw_section_header(
    layer: &PdfLayerReference,
    font_bold: &IndirectFontRef,
    title: &str,
    y_pos: &mut f32,
) {
    layer.use_text(title, FONT_SIZE_HEADING, Mm(20.0), Mm(*y_pos), font_bold);
    *y_pos -= 10.0;
}

fn draw_device_table_header(layer: &PdfLayerReference, font_bold: &IndirectFontRef, y_pos: &mut f32) {
    layer.use_text(
        "IP Address",
        FONT_SIZE_BODY,
        Mm(DEVICE_COL_IP_X),
        Mm(*y_pos),
        font_bold,
    );
    layer.use_text(
        "Hostname",
        FONT_SIZE_BODY,
        Mm(DEVICE_COL_HOSTNAME_X),
        Mm(*y_pos),
        font_bold,
    );
    layer.use_text(
        "Device Type",
        FONT_SIZE_BODY,
        Mm(DEVICE_COL_TYPE_X),
        Mm(*y_pos),
        font_bold,
    );
    layer.use_text(
        "Risk Score",
        FONT_SIZE_BODY,
        Mm(DEVICE_COL_RISK_X),
        Mm(*y_pos),
        font_bold,
    );
    *y_pos -= 8.0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_scan_report_pdf() {
        let scan = ScanResult {
            interface_name: "eth0".to_string(),
            local_ip: "192.168.1.100".to_string(),
            local_mac: "00:11:22:33:44:55".to_string(),
            subnet: "192.168.1.0/24".to_string(),
            scan_method: "ARP+ICMP+TCP".to_string(),
            arp_discovered: 1,
            icmp_discovered: 1,
            total_hosts: 1,
            scan_duration_ms: 12500,
            active_hosts: vec![],
        };

        let devices = vec![HostInfo {
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            hostname: Some("router".to_string()),
            vendor: Some("TP-Link".to_string()),
            device_type: "Router".to_string(),
            os_guess: Some("Linux".to_string()),
            risk_score: 15,
            open_ports: vec![80, 443],
            response_time_ms: Some(5),
            is_randomized: false,
            ttl: Some(64),
            discovery_method: "ARP+ICMP+TCP".to_string(),
            system_description: None,
            uptime_seconds: None,
            neighbors: vec![],
            vulnerabilities: vec![],
            port_warnings: vec![],
            security_grade: String::new(),
        }];

        let result = generate_scan_report_pdf(&scan, &devices, None);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }
}
