//! PDF export functionality
//!
//! Generate professional PDF reports using krilla.

use crate::database::NetworkStats;
use crate::insights::SecurityReport;
use crate::models::{HostInfo, ScanResult};
use anyhow::{Result, anyhow};
use chrono::Utc;
use krilla::Document;
use krilla::geom::Point;
use krilla::page::PageSettings;
use krilla::text::{Font, TextDirection};
use std::path::PathBuf;

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

fn mm_to_pt(mm: f32) -> f32 {
    mm * 72.0 / 25.4
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

fn font_candidate_paths() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut regular = Vec::new();
    let mut bold = Vec::new();

    if cfg!(target_os = "windows") {
        let windir = std::env::var_os("WINDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let fonts = windir.join("Fonts");
        regular.push(fonts.join("arial.ttf"));
        regular.push(fonts.join("segoeui.ttf"));
        regular.push(fonts.join("calibri.ttf"));
        bold.push(fonts.join("arialbd.ttf"));
        bold.push(fonts.join("segoeuib.ttf"));
        bold.push(fonts.join("calibrib.ttf"));
    } else if cfg!(target_os = "macos") {
        regular.push(PathBuf::from(
            "/System/Library/Fonts/Supplemental/Arial.ttf",
        ));
        regular.push(PathBuf::from(
            "/System/Library/Fonts/Supplemental/Helvetica.ttf",
        ));
        regular.push(PathBuf::from("/Library/Fonts/Arial.ttf"));
        bold.push(PathBuf::from(
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        ));
        bold.push(PathBuf::from(
            "/System/Library/Fonts/Supplemental/Helvetica Bold.ttf",
        ));
        bold.push(PathBuf::from("/Library/Fonts/Arial Bold.ttf"));
    } else {
        regular.push(PathBuf::from(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ));
        regular.push(PathBuf::from(
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        ));
        regular.push(PathBuf::from(
            "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        ));
        bold.push(PathBuf::from(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ));
        bold.push(PathBuf::from(
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        ));
        bold.push(PathBuf::from(
            "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
        ));
    }

    (regular, bold)
}

fn load_font(paths: &[PathBuf]) -> Option<Font> {
    for path in paths {
        if let Ok(bytes) = std::fs::read(path)
            && let Some(font) = Font::new(bytes.into(), 0)
        {
            return Some(font);
        }
    }
    None
}

fn load_report_fonts() -> Result<(Font, Font)> {
    let (regular_paths, bold_paths) = font_candidate_paths();
    let regular = load_font(&regular_paths).ok_or_else(|| {
        anyhow!(
            "No compatible system font found for PDF export. Tried: {}",
            regular_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;

    let bold = load_font(&bold_paths).unwrap_or_else(|| regular.clone());
    Ok((regular, bold))
}

fn build_pdf_bytes(_title: &str, pages: Vec<Vec<TextLine>>) -> Result<Vec<u8>> {
    let (regular_font, bold_font) = load_report_fonts()?;
    let mut doc = Document::new();
    let page_settings = PageSettings::from_wh(mm_to_pt(PAGE_WIDTH_MM), mm_to_pt(PAGE_HEIGHT_MM))
        .ok_or_else(|| anyhow!("Invalid PDF page size"))?;

    for lines in pages {
        let mut page = doc.start_page_with(page_settings.clone());
        let mut surface = page.surface();

        for line in lines {
            let font = if line.bold {
                bold_font.clone()
            } else {
                regular_font.clone()
            };
            surface.draw_text(
                Point::from_xy(mm_to_pt(line.x_mm), mm_to_pt(line.y_mm)),
                font,
                line.size_pt,
                &line.text,
                false,
                TextDirection::Auto,
            );
        }

        surface.finish();
        page.finish();
    }

    doc.finish()
        .map_err(|e| anyhow!("Failed to serialize PDF document: {:?}", e))
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

    build_pdf_bytes("Network Scan Report", pages)
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

    build_pdf_bytes("Network Health Report", pages)
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
        assert!(!result.expect("PDF should be generated").is_empty());
    }

    #[test]
    fn test_wrap_text_limits_line_width() {
        let text = "This is a long sentence that should be wrapped across multiple lines for PDF rendering correctness.";
        let lines = wrap_text(text, 24);
        assert!(!lines.is_empty());
        assert!(lines.iter().all(|line| line.chars().count() <= 24));
    }
}
