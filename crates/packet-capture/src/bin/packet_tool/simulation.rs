use std::cell::RefCell;
use std::collections::HashMap;

use prost::Message;
use vapor_forge_config::{AppId, RuntimeConfig};
use vapor_forge_features::achievements::{self, StatsSendPlan};
use vapor_forge_features::apps::OwnershipState;
use vapor_forge_features::request_code;
use vapor_forge_features::valve_filter::{self, PrivacyAction};
use vapor_forge_packet_capture::{
    format_summary, packet_summary_json, summarize_packet, PacketChange, PacketDirection,
    PacketSummary, PacketType, SummaryFormat,
};
use vapor_forge_steam_protocol::{
    CMsgProtoBufHeader, EncryptedAppTicketRequest, GetAppOwnershipTicketRequest,
    EMSG_CLIENT_RICH_PRESENCE_UPLOAD, EMSG_ENCRYPTED_APPTICKET_REQUEST, EMSG_GAMESPLAYED,
    EMSG_GAMESPLAYED_WITH_DATABLOB, EMSG_GET_APP_OWNERSHIP_TICKET, EMSG_PICS_PRODUCT_INFO_REQUEST,
    EMSG_REQUEST_USERSTATS, EMSG_SERVICE_METHOD_CALL_FROM_CLIENT, EMSG_STORE_USERSTATS,
    EMSG_STORE_USERSTATS2, K_MSG_HDR_PROTO_FLAG,
};

use super::cli::OutputFormat;
use super::input::Input;

#[derive(Clone, Debug)]
pub(super) struct SimulationResult {
    pub(super) decision: SimDecision,
    pub(super) handler: &'static str,
    pub(super) reason: String,
    pub(super) final_len: Option<usize>,
    pub(super) required_runtime_state: Vec<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SimDecision {
    Pass,
    Drop,
    Rewrite,
    NeedsRuntimeState,
}

impl SimDecision {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Drop => "drop",
            Self::Rewrite => "rewrite",
            Self::NeedsRuntimeState => "needs-runtime-state",
        }
    }
}

pub(super) struct SimulationContext<'a> {
    config: &'a RuntimeConfig,
    ownership: Option<&'a HashMap<AppId, OwnershipState>>,
    avatar_map: Option<&'a HashMap<AppId, AppId>>,
    stat_steam_ids: Option<&'a HashMap<AppId, u64>>,
    manifest_provider_available: Option<bool>,
    missing: RefCell<Vec<&'static str>>,
}

impl<'a> SimulationContext<'a> {
    fn offline(config: &'a RuntimeConfig) -> Self {
        Self {
            config,
            ownership: None,
            avatar_map: None,
            stat_steam_ids: None,
            manifest_provider_available: None,
            missing: RefCell::new(Vec::new()),
        }
    }

    #[cfg(test)]
    pub(super) fn complete(
        config: &'a RuntimeConfig,
        ownership: &'a HashMap<AppId, OwnershipState>,
        avatar_map: &'a HashMap<AppId, AppId>,
        stat_steam_ids: &'a HashMap<AppId, u64>,
        manifest_provider_available: bool,
    ) -> Self {
        Self {
            config,
            ownership: Some(ownership),
            avatar_map: Some(avatar_map),
            stat_steam_ids: Some(stat_steam_ids),
            manifest_provider_available: Some(manifest_provider_available),
            missing: RefCell::new(Vec::new()),
        }
    }

    fn ownership(&self, app_id: AppId) -> OwnershipState {
        match self.ownership {
            Some(ownership) => ownership
                .get(&app_id)
                .copied()
                .unwrap_or(OwnershipState::Unknown),
            None => {
                self.record_missing("actual ownership snapshot");
                OwnershipState::Unknown
            }
        }
    }

    fn avatar(&self, app_id: AppId) -> Option<AppId> {
        let Some(avatar_map) = self.avatar_map else {
            self.record_missing("Lua and launch-time AppAvatar state");
            return None;
        };
        avatar_map
            .get(&app_id)
            .copied()
            .or_else(|| avatar_map.get(&AppId(0)).copied())
    }

    fn stat_steam_ids(&self) -> Option<&HashMap<AppId, u64>> {
        self.stat_steam_ids
    }

    fn manifest_provider_available(&self) -> bool {
        match self.manifest_provider_available {
            Some(available) => available,
            None => {
                self.record_missing("manifest provider availability");
                true
            }
        }
    }

    fn record_missing(&self, dependency: &'static str) {
        let mut missing = self.missing.borrow_mut();
        if !missing.contains(&dependency) {
            missing.push(dependency);
        }
    }

    fn missing(&self) -> Vec<&'static str> {
        self.missing.borrow().clone()
    }
}

pub(super) fn simulate_offline(
    input: Input,
    direction: PacketDirection,
    config_path: Option<String>,
    format: OutputFormat,
) -> Result<(), String> {
    let bytes = input.read()?;
    let config = load_sim_config(config_path.as_deref())?;
    let summary = summarize_packet(0, direction, &bytes, PacketChange::Unchanged, None);
    let result = match direction {
        PacketDirection::Send => simulate_send(&bytes, &config),
        PacketDirection::Recv => simulate_recv(&summary),
    };

    match format {
        OutputFormat::Text => {
            println!("{}", format_summary(&summary, SummaryFormat::Offline));
            println!(
                "  simulate: decision={} handler={} final_len={}",
                result.decision.label(),
                result.handler,
                result
                    .final_len
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_owned())
            );
            println!("  reason: {}", result.reason);
            if !result.required_runtime_state.is_empty() {
                println!("  required runtime state:");
                for dependency in result.required_runtime_state {
                    println!("    - {dependency}");
                }
            }
            Ok(())
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "summary": packet_summary_json(&summary),
                    "simulation": simulation_json(&result),
                })
            );
            Ok(())
        }
    }
}

fn load_sim_config(path: Option<&str>) -> Result<RuntimeConfig, String> {
    match path {
        Some(path) => RuntimeConfig::load(std::path::Path::new(path))
            .map_err(|error| format!("load config {path:?} failed: {error}")),
        None => Ok(RuntimeConfig::default()),
    }
}

pub(super) fn simulate_send(data: &[u8], config: &RuntimeConfig) -> SimulationResult {
    simulate_send_with_context(data, &SimulationContext::offline(config))
}

pub(super) fn simulate_send_with_context(
    data: &[u8],
    context: &SimulationContext<'_>,
) -> SimulationResult {
    let Some((emsg_raw, header_bytes, body_bytes)) = vapor_forge_steam_protocol::unpack_raw(data)
    else {
        return sim_result(
            SimDecision::Pass,
            "decode",
            "invalid Steam packet framing; send hook passes the frame through",
            None,
        );
    };
    let emsg = emsg_raw & !K_MSG_HDR_PROTO_FLAG;
    if emsg_raw & K_MSG_HDR_PROTO_FLAG == 0 {
        return sim_result(
            SimDecision::Pass,
            "non-proto",
            "non-protobuf packet; send hook does not mutate it",
            None,
        );
    }

    match emsg {
        EMSG_SERVICE_METHOD_CALL_FROM_CLIENT => {
            simulate_service_method(emsg_raw, header_bytes, body_bytes, context)
        }
        EMSG_REQUEST_USERSTATS => {
            simulate_legacy_stats(emsg_raw, header_bytes, body_bytes, context)
        }
        EMSG_STORE_USERSTATS | EMSG_STORE_USERSTATS2 => {
            simulate_store_stats(emsg, header_bytes, body_bytes, context)
        }
        EMSG_GET_APP_OWNERSHIP_TICKET => simulate_ticket(
            GetAppOwnershipTicketRequest::decode(body_bytes)
                .ok()
                .and_then(|request| request.app_id)
                .map(AppId),
            "ownership-ticket-privacy",
            context,
        ),
        EMSG_ENCRYPTED_APPTICKET_REQUEST => simulate_ticket(
            EncryptedAppTicketRequest::decode(body_bytes)
                .ok()
                .and_then(|request| request.app_id)
                .map(AppId),
            "encrypted-ticket-privacy",
            context,
        ),
        EMSG_GAMESPLAYED | EMSG_GAMESPLAYED_WITH_DATABLOB => {
            simulate_games_played(emsg_raw, header_bytes, body_bytes, context)
        }
        EMSG_CLIENT_RICH_PRESENCE_UPLOAD => needs_runtime(
            "rich-presence-privacy",
            "the production decision uses the GamesPlayed-derived blocked-app state",
            vec!["tracked GamesPlayed and AppAvatar state"],
        ),
        EMSG_PICS_PRODUCT_INFO_REQUEST => needs_runtime(
            "pics-access-token",
            "the production rewrite uses access tokens loaded by the Lua runtime",
            vec!["Lua access-token state"],
        ),
        _ => sim_result(
            SimDecision::Pass,
            "unknown",
            "no send-side handler matched",
            None,
        ),
    }
}

fn simulate_service_method(
    emsg_raw: u32,
    header_bytes: &[u8],
    body_bytes: &[u8],
    context: &SimulationContext<'_>,
) -> SimulationResult {
    let Ok(header) = CMsgProtoBufHeader::decode(header_bytes) else {
        return sim_result(
            SimDecision::Pass,
            "service-method",
            "protobuf header failed to decode; send hook passes the frame through",
            None,
        );
    };
    let Some(method) = header.target_job_name.as_deref() else {
        return sim_result(
            SimDecision::Pass,
            "service-method",
            "missing target_job_name; send hook passes the frame through",
            None,
        );
    };

    if method == request_code::TARGET_JOB_NAME {
        return simulate_manifest_request(&header, header_bytes, body_bytes, context);
    }

    let cloud = vapor_forge_cloud_rpc::privacy_fallback_with_ownership(
        method,
        body_bytes,
        context.config,
        |app_id| context.ownership(app_id),
    );
    if !context.missing().is_empty() {
        return missing_runtime_result(
            "cloud-privacy",
            "the Cloud routing decision depends on genuine ownership",
            context,
        );
    }
    if let Some((app_id, _)) = cloud {
        return sim_result(
            SimDecision::Drop,
            "cloud-privacy",
            format!("shared Cloud privacy plan keeps app {app_id} off Valve"),
            Some(0),
        );
    }
    if context.config.cumulus_configured()
        && matches!(
            method,
            vapor_forge_cloud_rpc::CDN_REPORT | vapor_forge_cloud_rpc::EXTERNAL_TRANSFER_REPORT
        )
    {
        return needs_runtime(
            "cloud-transfer-report",
            "transfer-report interception depends on the live transfer-target registry",
            vec!["Cumulus transfer-target registry"],
        );
    }

    let privacy = valve_filter::service_method_action_with_ownership(
        &header,
        header_bytes,
        body_bytes,
        context.config,
        |app_id| context.ownership(app_id),
    );
    if !context.missing().is_empty() {
        return missing_runtime_result(
            "valve-service-privacy",
            "the shared Valve privacy plan depends on genuine ownership",
            context,
        );
    }
    if privacy != PrivacyAction::Pass {
        return privacy_result(privacy, "valve-service-privacy");
    }

    if method == achievements::STATS_JOB_NAME {
        return simulate_service_stats(emsg_raw, header_bytes, body_bytes, &header, context);
    }

    sim_result(
        SimDecision::Pass,
        "service-method",
        format!("no production handler matched service method {method:?}"),
        None,
    )
}

fn simulate_manifest_request(
    header: &CMsgProtoBufHeader,
    header_bytes: &[u8],
    body_bytes: &[u8],
    context: &SimulationContext<'_>,
) -> SimulationResult {
    let fetch = match request_code::plan_fetch(header, header_bytes, body_bytes) {
        Ok(fetch) => fetch,
        Err(request_code::ManifestFetchError::Decode(_)) => {
            return sim_result(
                SimDecision::Pass,
                "manifest-request-code",
                "shared manifest plan could not decode the request",
                None,
            );
        }
        Err(request_code::ManifestFetchError::MissingJobId) => {
            return sim_result(
                SimDecision::Pass,
                "manifest-request-code",
                "shared manifest plan requires a nonzero source job id",
                None,
            );
        }
    };
    let app_id = AppId(fetch.app_id);
    let ownership = context.ownership(app_id);
    let provider_available = context.manifest_provider_available();
    let intercept = request_code::should_intercept_with_ownership(
        app_id,
        context.config,
        provider_available,
        |_| ownership,
    );
    if !context.missing().is_empty() {
        return missing_runtime_result(
            "manifest-request-code",
            "manifest interception depends on genuine ownership",
            context,
        );
    }
    if !intercept {
        return sim_result(
            SimDecision::Pass,
            "manifest-request-code",
            format!("shared manifest plan passes app {} through", fetch.app_id),
            None,
        );
    }
    needs_runtime(
        "manifest-request-code",
        "interception is eligible, but the final send decision depends on queue capacity and provider startup",
        vec!["manifest provider and pending-queue state"],
    )
}

fn simulate_service_stats(
    emsg_raw: u32,
    header_bytes: &[u8],
    body_bytes: &[u8],
    header: &CMsgProtoBufHeader,
    context: &SimulationContext<'_>,
) -> SimulationResult {
    let empty = HashMap::new();
    let stat_steam_ids = context.stat_steam_ids().unwrap_or(&empty);
    let plan = achievements::plan_send_service_stats(
        header,
        body_bytes,
        context.config,
        stat_steam_ids,
        |app_id| context.ownership(app_id),
    );
    stats_plan_result(
        plan,
        emsg_raw,
        header_bytes,
        context,
        "achievement-service-stats",
    )
}

fn simulate_legacy_stats(
    emsg_raw: u32,
    header_bytes: &[u8],
    body_bytes: &[u8],
    context: &SimulationContext<'_>,
) -> SimulationResult {
    let empty = HashMap::new();
    let stat_steam_ids = context.stat_steam_ids().unwrap_or(&empty);
    let plan = achievements::plan_send_legacy_stats(
        body_bytes,
        context.config,
        stat_steam_ids,
        |app_id| context.ownership(app_id),
    );
    stats_plan_result(
        plan,
        emsg_raw,
        header_bytes,
        context,
        "achievement-legacy-stats",
    )
}

fn stats_plan_result(
    plan: StatsSendPlan,
    emsg_raw: u32,
    header_bytes: &[u8],
    context: &SimulationContext<'_>,
    handler: &'static str,
) -> SimulationResult {
    if !context.missing().is_empty() {
        return missing_runtime_result(
            handler,
            "the shared achievement plan depends on genuine ownership",
            context,
        );
    }
    match plan {
        StatsSendPlan::Pass => sim_result(
            SimDecision::Pass,
            handler,
            "shared achievement plan passes the request through",
            None,
        ),
        StatsSendPlan::DropOffline { app_id, .. } => sim_result(
            SimDecision::Drop,
            handler,
            format!("shared achievement plan serves app {} offline", app_id.0),
            Some(0),
        ),
        StatsSendPlan::Rewrite {
            app_id,
            body,
            donor_steam_id,
            ..
        } => {
            if context.stat_steam_ids().is_none() {
                return needs_runtime(
                    handler,
                    format!(
                        "app {} is eligible for rewrite, but its Lua donor SteamID is unavailable",
                        app_id.0
                    ),
                    vec!["Lua stat_steam_ids state"],
                );
            }
            let final_len =
                vapor_forge_steam_protocol::assemble_raw(emsg_raw, header_bytes, &body).len();
            sim_result(
                SimDecision::Rewrite,
                handler,
                format!(
                    "shared achievement plan rewrites app {} to donor SteamID {donor_steam_id}",
                    app_id.0
                ),
                Some(final_len),
            )
        }
    }
}

fn simulate_store_stats(
    emsg: u32,
    header_bytes: &[u8],
    body_bytes: &[u8],
    context: &SimulationContext<'_>,
) -> SimulationResult {
    let action = valve_filter::store_stats_action_with_ownership(
        emsg,
        header_bytes,
        body_bytes,
        context.config,
        |app_id| context.ownership(app_id),
    );
    if !context.missing().is_empty() {
        return missing_runtime_result(
            "store-stats-privacy",
            "the shared StoreStats plan depends on genuine ownership",
            context,
        );
    }
    privacy_result(action, "store-stats-privacy")
}

fn simulate_ticket(
    app_id: Option<AppId>,
    handler: &'static str,
    context: &SimulationContext<'_>,
) -> SimulationResult {
    let Some(app_id) = app_id.filter(|app_id| app_id.0 != 0) else {
        return sim_result(
            SimDecision::Pass,
            handler,
            "ticket body failed to decode or has no app_id",
            None,
        );
    };
    let protected =
        vapor_forge_features::apps::classify_app_with_ownership(context.config, app_id, |app_id| {
            context.ownership(app_id)
        })
        .requires_injected_ownership();
    if !context.missing().is_empty() {
        return missing_runtime_result(
            handler,
            "ticket routing depends on genuine ownership",
            context,
        );
    }
    if !protected {
        return sim_result(
            SimDecision::Pass,
            handler,
            format!("shared app authority passes app {} through", app_id.0),
            None,
        );
    }
    needs_runtime(
        handler,
        format!(
            "app {} needs a local response whose contents depend on ticket runtime state",
            app_id.0
        ),
        vec!["Lua, memory, and disk ticket caches"],
    )
}

fn simulate_games_played(
    emsg_raw: u32,
    header_bytes: &[u8],
    body_bytes: &[u8],
    context: &SimulationContext<'_>,
) -> SimulationResult {
    let Some(filtered) = valve_filter::filter_games_played_with_runtime(
        body_bytes,
        context.config,
        |app_id| context.avatar(app_id),
        |app_id| context.ownership(app_id),
    ) else {
        return sim_result(
            SimDecision::Pass,
            "games-played-privacy",
            "shared GamesPlayed plan could not decode the body",
            None,
        );
    };
    if !context.missing().is_empty() {
        return missing_runtime_result(
            "games-played-privacy",
            "the shared GamesPlayed plan queried runtime AppAvatar or ownership state",
            context,
        );
    }
    match filtered.body {
        Some(body) => sim_result(
            SimDecision::Rewrite,
            "games-played-privacy",
            "shared GamesPlayed plan rewrites or removes at least one entry",
            Some(vapor_forge_steam_protocol::assemble_raw(emsg_raw, header_bytes, &body).len()),
        ),
        None => sim_result(
            SimDecision::Pass,
            "games-played-privacy",
            "shared GamesPlayed plan leaves the body unchanged",
            None,
        ),
    }
}

fn privacy_result(action: PrivacyAction, handler: &'static str) -> SimulationResult {
    match action {
        PrivacyAction::Pass => sim_result(
            SimDecision::Pass,
            handler,
            "shared privacy plan passes the request through",
            None,
        ),
        PrivacyAction::Drop { app_id } => sim_result(
            SimDecision::Drop,
            handler,
            format!("shared privacy plan drops app {app_id}"),
            Some(0),
        ),
        PrivacyAction::Respond { app_id, .. } => sim_result(
            SimDecision::Drop,
            handler,
            format!("shared privacy plan queues a local response for app {app_id}"),
            Some(0),
        ),
    }
}

fn simulate_recv(summary: &PacketSummary) -> SimulationResult {
    match summary.packet_type {
        PacketType::Stats => needs_runtime(
            "achievement-stats-response",
            "recv stats rewriting depends on pending request state",
            vec!["pending achievement request state"],
        ),
        PacketType::EncryptedTicket => needs_runtime(
            "encrypted-ticket",
            "encrypted ticket rewriting depends on cache and Lua state",
            vec!["Lua, memory, and disk ticket caches"],
        ),
        PacketType::Persona => needs_runtime(
            "persona-rich-presence",
            "PersonaState patching depends on cached self persona and tracked rich presence",
            vec!["local SteamID, persona cache, and rich-presence state"],
        ),
        _ => sim_result(
            SimDecision::Pass,
            "unknown",
            "no recv-side production handler matched this packet type",
            None,
        ),
    }
}

fn simulation_json(result: &SimulationResult) -> serde_json::Value {
    serde_json::json!({
        "decision": result.decision.label(),
        "handler": result.handler,
        "reason": result.reason,
        "final_len": result.final_len,
        "required_runtime_state": result.required_runtime_state,
    })
}

fn missing_runtime_result(
    handler: &'static str,
    reason: impl Into<String>,
    context: &SimulationContext<'_>,
) -> SimulationResult {
    needs_runtime(handler, reason, context.missing())
}

fn needs_runtime(
    handler: &'static str,
    reason: impl Into<String>,
    required: Vec<&'static str>,
) -> SimulationResult {
    sim_result_with_assumptions(
        SimDecision::NeedsRuntimeState,
        handler,
        reason,
        None,
        required,
    )
}

fn sim_result(
    decision: SimDecision,
    handler: &'static str,
    reason: impl Into<String>,
    final_len: Option<usize>,
) -> SimulationResult {
    sim_result_with_assumptions(decision, handler, reason, final_len, Vec::new())
}

fn sim_result_with_assumptions(
    decision: SimDecision,
    handler: &'static str,
    reason: impl Into<String>,
    final_len: Option<usize>,
    required_runtime_state: Vec<&'static str>,
) -> SimulationResult {
    SimulationResult {
        decision,
        handler,
        reason: reason.into(),
        final_len,
        required_runtime_state,
    }
}
