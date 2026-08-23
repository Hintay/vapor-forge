mod capture;
mod cli;
mod input;
mod offline;
mod simulation;

use capture::{json_suffix, print_response, send_debug_command, watch};
use cli::{capture_command, filter_suffix, resolve_socket, Args, Command};
#[cfg(test)]
use cli::{CaptureCommand, OutputFormat};
#[cfg(test)]
use input::parse_hex_dump;
use offline::{decode_offline, explain_offline};
use simulation::simulate_offline;
#[cfg(test)]
use simulation::{simulate_send, simulate_send_with_context, SimDecision, SimulationContext};

pub(super) fn run() -> Result<(), String> {
    let Args {
        socket,
        format,
        command,
    } = Args::parse(std::env::args().skip(1))?;
    match command {
        Command::Capture(capture) => {
            let command = capture_command(capture, format);
            print_response(
                &send_debug_command(&resolve_socket(socket.as_deref())?, &command)?,
                format,
            )
        }
        Command::List(filters) => {
            let command = format!(
                "packet list{}{}",
                filter_suffix(&filters),
                json_suffix(format)
            );
            print_response(
                &send_debug_command(&resolve_socket(socket.as_deref())?, &command)?,
                format,
            )
        }
        Command::Show(id) => {
            let command = format!("packet show {id}{}", json_suffix(format));
            print_response(
                &send_debug_command(&resolve_socket(socket.as_deref())?, &command)?,
                format,
            )
        }
        Command::Save { id, path } => {
            let command = format!("packet save {id} {path}{}", json_suffix(format));
            print_response(
                &send_debug_command(&resolve_socket(socket.as_deref())?, &command)?,
                format,
            )
        }
        Command::Watch { filters, interval } => {
            watch(&resolve_socket(socket.as_deref())?, filters, interval)
        }
        Command::Decode { input, direction } => decode_offline(input, direction, format),
        Command::Explain { input, direction } => explain_offline(input, direction, format),
        Command::Simulate {
            input,
            direction,
            config,
        } => simulate_offline(input, direction, config, format),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::collections::HashMap;
    use vapor_forge_config::{AppId, RuntimeConfig};
    use vapor_forge_features::apps::OwnershipState;
    use vapor_forge_packet_capture::PacketDirection;
    use vapor_forge_steam_protocol::{
        CMsgClientGamesPlayed, CMsgProtoBufHeader, GetManifestRequestCodeRequest, EMSG_GAMESPLAYED,
        EMSG_SERVICE_METHOD_CALL_FROM_CLIENT, EMSG_STORE_USERSTATS, K_MSG_HDR_PROTO_FLAG,
    };

    #[derive(Clone, prost::Message)]
    struct LegacyStoreUserStatsRequestFixture {
        #[prost(fixed64, optional, tag = "1")]
        game_id: Option<u64>,
    }

    fn controlled_config(app_id: u32) -> RuntimeConfig {
        let mut config = RuntimeConfig::default();
        config.apps.inject.push(vapor_forge_config::InjectApp {
            id: AppId(app_id),
            dlc: Vec::new(),
            ticket: vapor_forge_config::TicketMode::Forge,
            purchase_time: 0,
        });
        config
    }

    #[test]
    fn parses_hex_dump_with_offsets_and_punctuation() {
        assert_eq!(
            parse_hex_dump("0000: 01 02 0x03, bytes=04\n0004: 0506").unwrap(),
            vec![1, 2, 3, 4, 5, 6]
        );
    }

    #[test]
    fn capture_commands_honor_output_format() {
        assert_eq!(
            capture_command(CaptureCommand::Status, OutputFormat::Text),
            "packet capture status"
        );
        assert_eq!(
            capture_command(CaptureCommand::Status, OutputFormat::Json),
            "packet capture status --json"
        );
        assert_eq!(
            capture_command(CaptureCommand::Off, OutputFormat::Json),
            "packet capture off --json"
        );
    }

    #[test]
    fn explain_command_defaults_to_recv() {
        let args =
            Args::parse(["--format", "json", "explain", "--hex", "010203"].map(str::to_owned))
                .unwrap();
        assert_eq!(args.format, OutputFormat::Json);
        match args.command {
            Command::Explain { direction, .. } => assert_eq!(direction, PacketDirection::Recv),
            _ => panic!("expected explain command"),
        }
    }

    #[test]
    fn explain_command_accepts_send_direction_prefix() {
        let args = Args::parse(["explain", "send", "--hex", "010203"].map(str::to_owned)).unwrap();
        match args.command {
            Command::Explain { direction, .. } => assert_eq!(direction, PacketDirection::Send),
            _ => panic!("expected explain command"),
        }
    }

    #[test]
    fn simulate_command_defaults_to_send_and_accepts_config() {
        let args = Args::parse(
            ["simulate", "--config", "config.toml", "--hex", "010203"].map(str::to_owned),
        )
        .unwrap();
        match args.command {
            Command::Simulate {
                direction, config, ..
            } => {
                assert_eq!(direction, PacketDirection::Send);
                assert_eq!(config.as_deref(), Some("config.toml"));
            }
            _ => panic!("expected simulate command"),
        }
    }

    #[test]
    fn simulate_manifest_request_requires_runtime_ownership() {
        let header = CMsgProtoBufHeader {
            steamid: None,
            jobid_source: Some(42),
            jobid_target: None,
            target_job_name: Some(
                vapor_forge_steam_protocol::MANIFEST_REQUEST_CODE_JOB_NAME.to_owned(),
            ),
            eresult: None,
            transport_error: None,
            seq_num: None,
            ..Default::default()
        };
        let body = GetManifestRequestCodeRequest {
            app_id: Some(480),
            depot_id: Some(481),
            manifest_id: Some(123),
            ..Default::default()
        };
        let packet = vapor_forge_steam_protocol::assemble_raw(
            EMSG_SERVICE_METHOD_CALL_FROM_CLIENT | K_MSG_HDR_PROTO_FLAG,
            &header.encode_to_vec(),
            &body.encode_to_vec(),
        );
        let config = controlled_config(480);

        let result = simulate_send(&packet, &config);
        assert_eq!(result.decision, SimDecision::NeedsRuntimeState);
        assert_eq!(result.handler, "manifest-request-code");
        assert_eq!(result.final_len, None);
        assert_eq!(
            result.required_runtime_state,
            vec!["actual ownership snapshot"]
        );
    }

    #[test]
    fn simulate_manifest_request_stays_local_without_a_provider() {
        let app_id = AppId(480);
        let header = CMsgProtoBufHeader {
            jobid_source: Some(42),
            target_job_name: Some(
                vapor_forge_steam_protocol::MANIFEST_REQUEST_CODE_JOB_NAME.to_owned(),
            ),
            ..Default::default()
        };
        let body = GetManifestRequestCodeRequest {
            app_id: Some(app_id.0),
            depot_id: Some(481),
            manifest_id: Some(123),
            ..Default::default()
        };
        let packet = vapor_forge_steam_protocol::assemble_raw(
            EMSG_SERVICE_METHOD_CALL_FROM_CLIENT | K_MSG_HDR_PROTO_FLAG,
            &header.encode_to_vec(),
            &body.encode_to_vec(),
        );
        let mut config = controlled_config(app_id.0);
        config.manifest.providers.clear();
        let ownership = HashMap::from([(app_id, OwnershipState::Unowned)]);
        let avatars = HashMap::new();
        let donors = HashMap::new();
        let context = SimulationContext::complete(&config, &ownership, &avatars, &donors);

        let result = simulate_send_with_context(&packet, &context);
        assert_eq!(result.decision, SimDecision::NeedsRuntimeState);
        assert_eq!(result.handler, "manifest-request-code");
        assert_eq!(
            result.required_runtime_state,
            vec!["native response delivery state"]
        );
    }

    #[test]
    fn simulate_store_stats_requires_runtime_ownership() {
        let body = LegacyStoreUserStatsRequestFixture {
            game_id: Some(736_260),
        };
        let packet = vapor_forge_steam_protocol::assemble_raw(
            EMSG_STORE_USERSTATS | K_MSG_HDR_PROTO_FLAG,
            &CMsgProtoBufHeader::default().encode_to_vec(),
            &body.encode_to_vec(),
        );
        let result = simulate_send(&packet, &controlled_config(736_260));
        assert_eq!(result.decision, SimDecision::NeedsRuntimeState);
        assert_eq!(result.handler, "store-stats-privacy");
        assert_eq!(
            result.required_runtime_state,
            vec!["actual ownership snapshot"]
        );
    }

    #[test]
    fn simulate_games_played_requires_complete_runtime_maps() {
        let body = CMsgClientGamesPlayed {
            games_played: vec![vapor_forge_steam_protocol::GamePlayed {
                game_id: Some(736_260),
                ..Default::default()
            }],
            ..Default::default()
        };
        let packet = vapor_forge_steam_protocol::assemble_raw(
            EMSG_GAMESPLAYED | K_MSG_HDR_PROTO_FLAG,
            &CMsgProtoBufHeader::default().encode_to_vec(),
            &body.encode_to_vec(),
        );
        let result = simulate_send(&packet, &controlled_config(736_260));
        assert_eq!(result.decision, SimDecision::NeedsRuntimeState);
        assert_eq!(result.handler, "games-played-privacy");
        assert_eq!(
            result.required_runtime_state,
            vec![
                "Lua and launch-time AppAvatar state",
                "actual ownership snapshot"
            ]
        );
    }

    #[test]
    fn complete_runtime_state_uses_shared_store_stats_decision() {
        let app_id = AppId(736_265);
        let config = controlled_config(app_id.0);
        let ownership = HashMap::from([(app_id, OwnershipState::Unowned)]);
        let avatars = HashMap::new();
        let donors = HashMap::new();
        let context = SimulationContext::complete(&config, &ownership, &avatars, &donors);
        let body = LegacyStoreUserStatsRequestFixture {
            game_id: Some(u64::from(app_id.0)),
        };
        let packet = vapor_forge_steam_protocol::assemble_raw(
            EMSG_STORE_USERSTATS | K_MSG_HDR_PROTO_FLAG,
            &CMsgProtoBufHeader::default().encode_to_vec(),
            &body.encode_to_vec(),
        );

        let result = simulate_send_with_context(&packet, &context);
        assert_eq!(result.decision, SimDecision::Drop);
        assert_eq!(result.final_len, Some(0));
        assert!(result.required_runtime_state.is_empty());
    }

    #[test]
    fn complete_runtime_state_uses_shared_games_played_rewrite() {
        let app_id = AppId(736_266);
        let config = controlled_config(app_id.0);
        let ownership = HashMap::from([(app_id, OwnershipState::Unowned)]);
        let avatars = HashMap::new();
        let donors = HashMap::new();
        let context = SimulationContext::complete(&config, &ownership, &avatars, &donors);
        let body = CMsgClientGamesPlayed {
            games_played: vec![vapor_forge_steam_protocol::GamePlayed {
                game_id: Some(u64::from(app_id.0)),
                ..Default::default()
            }],
            ..Default::default()
        };
        let packet = vapor_forge_steam_protocol::assemble_raw(
            EMSG_GAMESPLAYED | K_MSG_HDR_PROTO_FLAG,
            &CMsgProtoBufHeader::default().encode_to_vec(),
            &body.encode_to_vec(),
        );

        let result = simulate_send_with_context(&packet, &context);
        assert_eq!(result.decision, SimDecision::Rewrite);
        assert!(result.required_runtime_state.is_empty());
    }
}
