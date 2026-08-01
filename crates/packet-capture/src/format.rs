use std::fmt::Write;

#[cfg(feature = "json")]
use crate::CapturedPacket;
use crate::{PacketCaptureFilter, PacketSummary};

#[cfg(feature = "json")]
const RAW_HEX_PREFIX_BYTES: usize = 96;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SummaryFormat {
    Offline,
    Captured,
}

pub fn format_summary(summary: &PacketSummary, style: SummaryFormat) -> String {
    let emsg = summary
        .emsg
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let apps = if summary.app_ids.is_empty() {
        "-".to_owned()
    } else {
        format!("{:?}", summary.app_ids)
    };

    match style {
        SummaryFormat::Offline => format!(
            "{} emsg={} type={} app={} change={} len={}",
            summary.direction.label(),
            emsg,
            summary.packet_type.label(),
            apps,
            summary.change.label(),
            summary.original_len
        ),
        SummaryFormat::Captured => {
            let len = match summary.final_len {
                Some(final_len) if final_len != summary.original_len => {
                    format!("{}->{final_len}", summary.original_len)
                }
                _ => summary.original_len.to_string(),
            };
            format!(
                "#{:<4} {:<4} emsg={:<5} type={:<16} app={} change={:<13} len={}",
                summary.id,
                summary.direction.label(),
                emsg,
                summary.packet_type.label(),
                apps,
                summary.change.label(),
                len
            )
        }
    }
}

pub fn format_capture_filter(filter: &PacketCaptureFilter) -> String {
    let mut parts = Vec::new();
    if let Some(direction) = filter.direction {
        parts.push(format!("direction={}", direction.label()));
    }
    if let Some(packet_type) = filter.packet_type {
        parts.push(format!("type={}", packet_type.label()));
    }
    if let Some(emsg) = filter.emsg {
        parts.push(format!("emsg={emsg}"));
    }
    if let Some(app_id) = filter.app_id {
        parts.push(format!("app={app_id}"));
    }
    if let Some(changed) = filter.changed {
        parts.push(format!("changed={}", changed.label()));
    }
    if parts.is_empty() {
        "none".to_owned()
    } else {
        parts.join(",")
    }
}

pub fn hex_prefix(bytes: &[u8], max: usize) -> String {
    let mut out = String::new();
    for byte in bytes.iter().take(max) {
        let _ = write!(out, "{byte:02x}");
    }
    if bytes.len() > max {
        out.push_str("...");
    }
    out
}

#[cfg(feature = "json")]
pub fn packet_summary_json(summary: &PacketSummary) -> serde_json::Value {
    serde_json::json!({
        "id": summary.id,
        "direction": summary.direction.label(),
        "emsg_raw": summary.emsg_raw,
        "emsg": summary.emsg,
        "proto": summary.proto,
        "type": summary.packet_type.label(),
        "app_ids": summary.app_ids,
        "steamid": summary.steamid,
        "job": summary.job,
        "eresult": summary.eresult,
        "change": summary.change.label(),
        "original_len": summary.original_len,
        "final_len": summary.final_len,
        "header_len": summary.header_len,
        "body_len": summary.body_len,
        "decode_error": summary.decode_error,
    })
}

#[cfg(feature = "json")]
pub fn captured_packet_json(packet: &CapturedPacket) -> serde_json::Value {
    serde_json::json!({
        "summary": packet_summary_json(&packet.summary),
        "raw": packet.raw.as_ref().map(|raw| serde_json::json!({
            "len": raw.len(),
            "hex_prefix": hex_prefix(raw, RAW_HEX_PREFIX_BYTES),
        })),
    })
}

#[cfg(feature = "json")]
pub fn capture_filter_json(filter: &PacketCaptureFilter) -> serde_json::Value {
    serde_json::json!({
        "direction": filter.direction.map(crate::PacketDirection::label),
        "type": filter.packet_type.map(crate::PacketType::label),
        "emsg": filter.emsg,
        "app_id": filter.app_id,
        "changed": filter.changed.map(crate::PacketChange::label),
    })
}

/// Format the summary object returned by the debug API's JSON response.
#[cfg(feature = "json")]
pub fn format_captured_summary_json(summary: &serde_json::Value) -> String {
    let id = summary
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let direction = summary
        .get("direction")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let emsg = summary
        .get("emsg")
        .and_then(serde_json::Value::as_u64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let packet_type = summary
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let changed = summary
        .get("change")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("-");
    let app_ids = summary.get("app_ids").unwrap_or(&serde_json::Value::Null);
    format!(
        "#{id:<4} {direction:<4} emsg={emsg:<5} type={packet_type:<16} app={app_ids} change={changed}"
    )
}

#[cfg(test)]
mod tests {
    use crate::{PacketChange, PacketDirection, PacketType};

    use super::*;

    fn summary() -> PacketSummary {
        PacketSummary {
            id: 7,
            direction: PacketDirection::Recv,
            emsg_raw: Some(0x8000_0097),
            emsg: Some(151),
            proto: true,
            packet_type: PacketType::Cloud,
            app_ids: vec![480],
            steamid: Some(76_561_198_000_000_001),
            job: Some("Cloud.GetAppFileChangelist#1".into()),
            eresult: Some(1),
            change: PacketChange::Rewritten,
            original_len: 32,
            final_len: Some(40),
            header_len: Some(8),
            body_len: Some(16),
            decode_error: None,
        }
    }

    #[test]
    fn preserves_offline_and_capture_text_contracts() {
        let summary = summary();
        assert_eq!(
            format_summary(&summary, SummaryFormat::Offline),
            "recv emsg=151 type=cloud app=[480] change=rewritten len=32"
        );
        assert_eq!(
            format_summary(&summary, SummaryFormat::Captured),
            "#7    recv emsg=151   type=cloud            app=[480] change=rewritten     len=32->40"
        );
    }

    #[test]
    fn formats_capture_filter_in_stable_field_order() {
        let filter = PacketCaptureFilter {
            direction: Some(PacketDirection::Recv),
            packet_type: Some(PacketType::Cloud),
            emsg: Some(151),
            app_id: Some(480),
            changed: Some(PacketChange::Rewritten),
        };
        assert_eq!(
            format_capture_filter(&filter),
            "direction=recv,type=cloud,emsg=151,app=480,changed=rewritten"
        );
    }

    #[cfg(feature = "json")]
    #[test]
    fn preserves_summary_and_raw_json_contracts() {
        let summary = summary();
        let packet = CapturedPacket {
            summary,
            raw: Some(b"third".to_vec()),
        };
        let json = captured_packet_json(&packet);
        assert_eq!(json["summary"]["type"], "cloud");
        assert_eq!(json["summary"]["final_len"], 40);
        assert_eq!(json["raw"]["hex_prefix"], "7468697264");
    }
}
