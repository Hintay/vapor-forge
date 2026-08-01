use vapor_forge_packet_capture::{
    format_summary, packet_summary_json, summarize_packet, PacketChange, PacketDirection,
    PacketSummary, PacketType, SummaryFormat,
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
            println!("{}", format_summary(&summary, SummaryFormat::Offline));
            Ok(())
        }
        OutputFormat::Json => {
            println!("{}", packet_summary_json(&summary));
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
            println!("{}", format_summary(&summary, SummaryFormat::Offline));
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
                    "summary": packet_summary_json(&summary),
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
