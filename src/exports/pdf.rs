//! PDF export functionality
//!
//! Generate professional PDF reports using printpdf

use crate::database::NetworkStats;
use crate::insights::SecurityReport;
use crate::models::{HostInfo, ScanResult};
use anyhow::Result;
use chrono::Utc;
use printpdf::{
    BuiltinFont, Mm, Op, PdfDocument, PdfFontHandle, PdfPage, PdfSaveOptions, Point, Pt, TextItem,
};

const FONT_SIZE_TITLE: f32 = 24.0;
const FONT_SIZE_HEADING: f32 = 16.0;
const FONT_SIZE_SUBHEADING: f32 = 12.0;
const FONT_SIZE_BODY: f32 = 10.0;
const PAGE_WIDTH_MM: f32 = 210.0;
const PAGE_HEIGHT_MM: f32 = 297.0;
const PAGE_START_Y_MM: f32 = 270.0;
const PAGE_BOTTOM_Y_MM: f32 = 20.0;
const PAGE_MARGIN_X_MM: f32 = 20.0;

#[derive(Clone)]
struct TextLine {
    text: String,
    x_mm: f32,
    y_mm: f32,
    size_pt: f32,
    bold: bool,
}

fn new_page(pages: &mut Vec<Vec<TextLine>>) {
    pages.push(Vec::new());
}

fn current_page_mut(pages: &mut [Vec<TextLine>]) -> &mut Vec<TextLine> {
    let idx = pages.len().saturating_sub(1);
    &mut pages[idx]
}

fn ensure_space(
    pages: &mut Vec<Vec<TextLine>>,
    y_pos: &mut f32,
    min_y: f32,
    continuation_title: Option<&str>,
) {
    if *y_pos >= min_y {
        return;
    }

    new_page(pages);
    *y_pos = PAGE_START_Y_MM;

    if let Some(title) = continuation_title {
        add_line(
            pages.as_mut_slice(),
            y_pos,
            title.to_string(),
            PAGE_MARGIN_X_MM,
            FONT_SIZE_HEADING,
            true,
            10.0,
        );
    }
}

fn add_line(
    pages: &mut [Vec<TextLine>],
    y_pos: &mut f32,
    text: String,
    x_mm: f32,
    size_pt: f32,
    bold: bool,
    y_step_mm: f32,
) {
    current_page_mut(pages).push(TextLine {
        text,
        x_mm,
        y_mm: *y_pos,
        size_pt,
        bold,
    });
    *y_pos -= y_step_mm;
}

fn push_text_op(ops: &mut Vec<Op>, line: &TextLine) {
    let font = if line.bold {
        BuiltinFont::HelveticaBold
    } else {
        BuiltinFont::Helvetica
    };

    ops.push(Op::StartTextSection);
    ops.push(Op::SetFont {
        font: PdfFontHandle::Builtin(font),
        size: Pt(line.size_pt),
    });
    ops.push(Op::SetTextCursor {
        pos: Point::new(Mm(line.x_mm), Mm(line.y_mm)),
    });
    ops.push(Op::ShowText {
        items: vec![TextItem::Text(line.text.clone())],
    });
    ops.push(Op::EndTextSection);
}

fn build_pdf_bytes(title: &str, pages: Vec<Vec<TextLine>>) -> Vec<u8> {
    let mut doc = PdfDocument::new(title);
    let pdf_pages: Vec<PdfPage> = pages
        .into_iter()
        .map(|lines| {
            let mut ops = Vec::with_capacity(lines.len() * 5);
            for line in &lines {
                push_text_op(&mut ops, line);
            }
            PdfPage::new(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), ops)
        })
        .collect();

    doc.with_pages(pdf_pages);
    let mut warnings = Vec::new();
    doc.save(&PdfSaveOptions::default(), &mut warnings)
}

fn draw_section_header(pages: &mut [Vec<TextLine>], y_pos: &mut f32, title: &str) {
    add_line(
        pages,
        y_pos,
        title.to_string(),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_HEADING,
        true,
        10.0,
    );
}

fn draw_device_table_header(pages: &mut [Vec<TextLine>], y_pos: &mut f32) {
    add_line(
        pages,
        y_pos,
        "IP Address | Hostname | Device Type | Risk Score".to_string(),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_BODY,
        true,
        8.0,
    );
}

fn truncate_for_row(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        return value.to_string();
    }
    let mut out = value
        .chars()
        .take(max_len.saturating_sub(3))
        .collect::<String>();
    out.push_str("...");
    out
}

fn wrap_text(value: &str, max_chars: usize) -> Vec<String> {
    if max_chars == 0 {
        return vec![value.to_string()];
    }

    let mut lines = Vec::new();
    let mut current = String::new();

    for word in value.split_whitespace() {
        let word_len = word.chars().count();
        let current_len = current.chars().count();

        if current_len == 0 {
            if word_len <= max_chars {
                current.push_str(word);
            } else {
                let chars: Vec<char> = word.chars().collect();
                for chunk in chars.chunks(max_chars) {
                    lines.push(chunk.iter().collect());
                }
            }
            continue;
        }

        if current_len + 1 + word_len <= max_chars {
            current.push(' ');
            current.push_str(word);
            continue;
        }

        lines.push(std::mem::take(&mut current));
        if word_len <= max_chars {
            current.push_str(word);
        } else {
            let chars: Vec<char> = word.chars().collect();
            for chunk in chars.chunks(max_chars) {
                lines.push(chunk.iter().collect());
            }
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

/// Generate a scan report PDF
pub fn generate_scan_report_pdf(
    scan: &ScanResult,
    devices: &[HostInfo],
    stats: Option<&NetworkStats>,
) -> Result<Vec<u8>> {
    let mut pages: Vec<Vec<TextLine>> = vec![Vec::new()];
    let mut y_pos = PAGE_START_Y_MM;

    add_line(
        pages.as_mut_slice(),
        &mut y_pos,
        "Network Scan Report".to_string(),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_TITLE,
        true,
        15.0,
    );

    let scan_date = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    add_line(
        pages.as_mut_slice(),
        &mut y_pos,
        format!("Generated: {}", scan_date),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_BODY,
        false,
        10.0,
    );

    add_line(
        pages.as_mut_slice(),
        &mut y_pos,
        format!("Scanned Subnet: {}", scan.subnet),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_BODY,
        false,
        7.0,
    );

    add_line(
        pages.as_mut_slice(),
        &mut y_pos,
        format!("Total Devices Found: {}", scan.active_hosts.len()),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_BODY,
        false,
        7.0,
    );

    add_line(
        pages.as_mut_slice(),
        &mut y_pos,
        format!(
            "Scan Duration: {:.2}s",
            scan.scan_duration_ms as f64 / 1000.0
        ),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_BODY,
        false,
        20.0,
    );

    draw_section_header(pages.as_mut_slice(), &mut y_pos, "Executive Summary");

    let high_risk_count = devices.iter().filter(|d| d.risk_score >= 50).count();
    let low_latency_count = devices
        .iter()
        .filter(|d| d.response_time_ms.unwrap_or(999) < 10)
        .count();

    add_line(
        pages.as_mut_slice(),
        &mut y_pos,
        format!("* High-risk devices: {}", high_risk_count),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_BODY,
        false,
        7.0,
    );

    add_line(
        pages.as_mut_slice(),
        &mut y_pos,
        format!("* Low-latency devices: {}", low_latency_count),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_BODY,
        false,
        7.0,
    );

    if let Some(stats) = stats {
        add_line(
            pages.as_mut_slice(),
            &mut y_pos,
            format!("* Total known devices: {}", stats.total_devices),
            PAGE_MARGIN_X_MM,
            FONT_SIZE_BODY,
            false,
            7.0,
        );
        add_line(
            pages.as_mut_slice(),
            &mut y_pos,
            format!("* New devices detected: {}", stats.new_devices_24h),
            PAGE_MARGIN_X_MM,
            FONT_SIZE_BODY,
            false,
            15.0,
        );
    }

    draw_section_header(pages.as_mut_slice(), &mut y_pos, "Device Inventory");
    draw_device_table_header(pages.as_mut_slice(), &mut y_pos);

    for device in devices {
        ensure_space(
            &mut pages,
            &mut y_pos,
            PAGE_BOTTOM_Y_MM,
            Some("Device Inventory (continued)"),
        );

        if y_pos >= PAGE_START_Y_MM - 11.0 {
            draw_device_table_header(pages.as_mut_slice(), &mut y_pos);
        }

        let hostname = device.hostname.as_deref().unwrap_or("N/A");
        let row = format!(
            "{} | {} | {} | {}",
            truncate_for_row(&device.ip, 18),
            truncate_for_row(hostname, 22),
            truncate_for_row(&device.device_type, 20),
            device.risk_score
        );

        add_line(
            pages.as_mut_slice(),
            &mut y_pos,
            row,
            PAGE_MARGIN_X_MM,
            FONT_SIZE_BODY,
            false,
            6.0,
        );
    }

    Ok(build_pdf_bytes("Network Scan Report", pages))
}

/// Generate a network health PDF report
pub fn generate_network_health_pdf(recommendations: &SecurityReport) -> Result<Vec<u8>> {
    let mut pages: Vec<Vec<TextLine>> = vec![Vec::new()];
    let mut y_pos = PAGE_START_Y_MM;

    add_line(
        pages.as_mut_slice(),
        &mut y_pos,
        "Network Security Report".to_string(),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_TITLE,
        true,
        15.0,
    );

    let report_date = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    add_line(
        pages.as_mut_slice(),
        &mut y_pos,
        format!("Generated: {}", report_date),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_BODY,
        false,
        15.0,
    );

    draw_section_header(pages.as_mut_slice(), &mut y_pos, &recommendations.summary);
    y_pos -= 5.0;

    add_line(
        pages.as_mut_slice(),
        &mut y_pos,
        format!("Critical Issues: {}", recommendations.critical_count),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_BODY,
        false,
        7.0,
    );
    add_line(
        pages.as_mut_slice(),
        &mut y_pos,
        format!("High Priority: {}", recommendations.high_count),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_BODY,
        false,
        7.0,
    );
    add_line(
        pages.as_mut_slice(),
        &mut y_pos,
        format!("Total Recommendations: {}", recommendations.total_issues),
        PAGE_MARGIN_X_MM,
        FONT_SIZE_BODY,
        false,
        15.0,
    );

    draw_section_header(pages.as_mut_slice(), &mut y_pos, "Security Recommendations");

    for rec in &recommendations.recommendations {
        ensure_space(
            &mut pages,
            &mut y_pos,
            35.0,
            Some("Security Recommendations (continued)"),
        );

        let priority_text = format!("[{}] {}", rec.priority.as_str(), rec.title);
        add_line(
            pages.as_mut_slice(),
            &mut y_pos,
            priority_text,
            PAGE_MARGIN_X_MM,
            FONT_SIZE_SUBHEADING,
            true,
            7.0,
        );

        for line in wrap_text(&rec.description, 88) {
            ensure_space(
                &mut pages,
                &mut y_pos,
                35.0,
                Some("Security Recommendations (continued)"),
            );
            add_line(
                pages.as_mut_slice(),
                &mut y_pos,
                line,
                PAGE_MARGIN_X_MM + 5.0,
                FONT_SIZE_BODY,
                false,
                7.0,
            );
        }

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
            let wrapped_devices = wrap_text(&devices_text, 88);
            let wrapped_count = wrapped_devices.len();
            for (idx, line) in wrapped_devices.into_iter().enumerate() {
                ensure_space(
                    &mut pages,
                    &mut y_pos,
                    35.0,
                    Some("Security Recommendations (continued)"),
                );
                add_line(
                    pages.as_mut_slice(),
                    &mut y_pos,
                    line,
                    PAGE_MARGIN_X_MM + 5.0,
                    FONT_SIZE_BODY,
                    false,
                    if idx + 1 == wrapped_count { 10.0 } else { 7.0 },
                );
            }
        } else {
            y_pos -= 5.0;
        }
    }

    Ok(build_pdf_bytes("Network Health Report", pages))
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

    #[test]
    fn test_wrap_text_limits_line_width() {
        let text = "This is a long sentence that should be wrapped across multiple lines for PDF rendering correctness.";
        let lines = wrap_text(text, 24);
        assert!(!lines.is_empty());
        assert!(lines.iter().all(|line| line.chars().count() <= 24));
    }
}
