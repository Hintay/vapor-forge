use vapor_forge_packet_capture::{
    summarize_packet, PacketChange, PacketDirection, PacketSummary, PacketType,
};

use super::cli::OutputFormat;
use super::input::Input;

pub(super) fn decode_offline(
    input: Input,
    direction: PacketDirection,
    format: OutputFormat,
) -> Result<(), String> {
    let bytes = input.read()?;
    let summary = summarize_packet(0, direction, &bytes, PacketChange::Unchanged, None);
    match format {
        OutputFormat::Text => {
            println!("{}", format_summary(&summary));
            Ok(())
        }
        OutputFormat::Json => {
            println!("{}", summary_json(&summary));
            Ok(())
        }
    }
}

pub(super) fn explain_offline(
    input: Input,
    direction: PacketDirection,
    format: OutputFormat,
) -> Result<(), String> {
    let bytes = input.read()?;
    let summary = summarize_packet(0, direction, &bytes, PacketChange::Unchanged, None);
    let routes = explain_routes(&summary);
    match format {
        OutputFormat::Text => {
            println!("{}", format_summary(&summary));
            if routes.is_empty() {
                println!("  explain: no known handler route");
            } else {
                println!("  handler routes:");
                for route in routes {
                    println!("    - {route}");
                }
            }
            println!("  note: offline explain does not simulate runtime state");
            Ok(())
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "summary": summary_json_value(&summary),
                    "routes": routes,
                    "runtime_state": "not-simulated",
                })
            );
            Ok(())
        }
    }
}

fn explain_routes(summary: &PacketSummary) -> Vec<&'static str> {
    match (summary.direction, summary.packet_type) {
        (PacketDirection::Send, PacketType::ManifestCode) => {
            vec!["send: manifest request-code intercept/drop depends on config"]
        }
        (PacketDirection::Send, PacketType::Stats) => {
            vec!["send: schema requests and StoreStats privacy decisions depend on AppAuthority"]
        }
        (PacketDirection::Send, PacketType::OwnershipTicket) => {
            vec!["send: protected app ownership tickets are answered locally"]
        }
        (PacketDirection::Send, PacketType::EncryptedTicket) => {
            vec!["send: protected encrypted app tickets are answered locally"]
        }
        (PacketDirection::Send, PacketType::Metrics) => {
            vec!["send: protected app metrics are dropped"]
        }
        (PacketDirection::Send, PacketType::Cloud) => {
            vec!["send: protected Cloud RPC uses Cumulus or a local privacy response"]
        }
        (PacketDirection::Send, PacketType::AppMetadata) => {
            vec!["send: recognized read-only app query passes through unchanged"]
        }
        (PacketDirection::Send, PacketType::GamesPlayed) => {
            vec!["send: games-played avatar rewrite and delegate-window reset"]
        }
        (PacketDirection::Send, PacketType::RichPresence) => {
            vec!["send: rich-presence KV capture"]
        }
        (PacketDirection::Send, PacketType::Pics) => {
            vec!["send: PICS access-token injection depends on script state"]
        }
        (PacketDirection::Recv, PacketType::Stats) => {
            vec!["recv: achievement stats response patch depends on pending offline state"]
        }
        (PacketDirection::Recv, PacketType::EncryptedTicket) => {
            vec!["recv: encrypted ticket cache/injection depends on ticket cache and script state"]
        }
        (PacketDirection::Recv, PacketType::Persona) => {
            vec!["recv: PersonaState cache/patch depends on rich-presence tracking state"]
        }
        _ => Vec::new(),
    }
}

pub(super) fn format_summary(summary: &PacketSummary) -> String {
    let emsg = summary
        .emsg
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let apps = if summary.app_ids.is_empty() {
        "-".to_owned()
    } else {
        format!("{:?}", summary.app_ids)
    };
    format!(
        "{} emsg={} type={} app={} change={} len={}",
        summary.direction.label(),
        emsg,
        summary.packet_type.label(),
        apps,
        summary.change.label(),
        summary.original_len
    )
}

fn summary_json(summary: &PacketSummary) -> String {
    summary_json_value(summary).to_string()
}

pub(super) fn summary_json_value(summary: &PacketSummary) -> serde_json::Value {
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
