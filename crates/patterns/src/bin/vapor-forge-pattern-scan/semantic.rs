#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WrapperPolicy {
    ImplementationRequired,
    WrapperAllowed,
    NotApplicable,
}

fn wrapper_policy(name: &str) -> WrapperPolicy {
    match name {
        "IClientRemoteStorage::RunIPCFrame"
        | "IClientAppManager::RunIPCFrame"
        | "IClientApps::RunIPCFrame" => WrapperPolicy::WrapperAllowed,
        _ if name.starts_with("IClient") => WrapperPolicy::ImplementationRequired,
        _ => WrapperPolicy::NotApplicable,
    }
}

struct SemanticCheck {
    name: &'static str,
    label: &'static str,
    validate: fn(&[u8], usize) -> Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SemanticArch {
    X86,
    X86_64,
}

#[derive(Debug, Default)]
struct Evidence {
    missing: Vec<&'static str>,
}

impl Evidence {
    fn required<const N: usize>(requirements: [(&'static str, bool); N]) -> Self {
        let mut evidence = Self::default();
        for (label, present) in requirements {
            evidence.require(label, present);
        }
        evidence
    }

    fn require(&mut self, label: &'static str, present: bool) {
        if !present {
            self.missing.push(label);
        }
    }

    fn reject(&mut self, label: &'static str, present: bool) {
        if present {
            self.missing.push(label);
        }
    }

    fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }

    fn describe(&self) -> String {
        if self.missing.is_empty() {
            "semantic validation failed".to_owned()
        } else {
            format!("missing {}", self.missing.join(", "))
        }
    }
}

fn evidence_result(evidence: Option<Evidence>, detail: &'static str) -> Option<&'static str> {
    evidence?.is_complete().then_some(detail)
}

const STEAMCLIENT32_SEMANTIC_CHECKS: &[SemanticCheck] = &[
    SemanticCheck {
        name: "CUser::CheckAppOwnership",
        label: "CUser::CheckAppOwnership body",
        validate: validate_check_app_ownership32,
    },
    SemanticCheck {
        name: "CUser::GetSubscribedApps",
        label: "CUser::GetSubscribedApps body",
        validate: validate_get_subscribed_apps32,
    },
    SemanticCheck {
        name: "CSteamEngine::Init",
        label: "CSteamEngine::Init body",
        validate: validate_steam_engine_init32,
    },
    SemanticCheck {
        name: "CSteamEngine::SetAPICallResult",
        label: "CSteamEngine::SetAPICallResult body",
        validate: validate_set_api_call_result32,
    },
    SemanticCheck {
        name: "IClientRemoteStorage::RunIPCFrame",
        label: "IClientRemoteStorage::RunIPCFrame body",
        validate: validate_ipc_run_frame32,
    },
    SemanticCheck {
        name: "IClientAppManager::RunIPCFrame",
        label: "IClientAppManager::RunIPCFrame body",
        validate: validate_ipc_run_frame32,
    },
    SemanticCheck {
        name: "IClientApps::RunIPCFrame",
        label: "IClientApps::RunIPCFrame body",
        validate: validate_ipc_run_frame32,
    },
    SemanticCheck {
        name: "LoadDepotDecryptionKey",
        label: "LoadDepotDecryptionKey body",
        validate: validate_load_depot_key32,
    },
    SemanticCheck {
        name: "BuildDepotDependency",
        label: "BuildDepotDependency body",
        validate: validate_build_depot_dependency32,
    },
    SemanticCheck {
        name: "CWebSocketConnection::BBuildAndAsyncSendFrame",
        label: "CWebSocketConnection::BBuildAndAsyncSendFrame body",
        validate: validate_websocket_send_frame32,
    },
    SemanticCheck {
        name: "CCMConnection::RecvPkt",
        label: "CCMConnection::RecvPkt body",
        validate: validate_ccm_recv_pkt32,
    },
    SemanticCheck {
        name: "CHTTPRequestJob::Start",
        label: "CHTTPRequestJob::Start body",
        validate: validate_http_request_job_start32,
    },
    SemanticCheck {
        name: "CUser::MarkLicenseAsChanged",
        label: "CUser::MarkLicenseAsChanged body",
        validate: validate_mark_license_changed32,
    },
    SemanticCheck {
        name: "CUser::ProcessPendingLicenseUpdates",
        label: "CUser::ProcessPendingLicenseUpdates body",
        validate: validate_process_pending_license_updates32,
    },
    SemanticCheck {
        name: "CUtlMemory::Grow",
        label: "CUtlMemory::Grow body",
        validate: validate_cutl_memory_grow32,
    },
    SemanticCheck {
        name: "CConfigStore::WriteVdfFile",
        label: "CConfigStore::WriteVdfFile body",
        validate: validate_write_vdf_file32,
    },
    SemanticCheck {
        name: "CUser::SpawnProcess",
        label: "CUser::SpawnProcess body",
        validate: validate_spawn_process32,
    },
    SemanticCheck {
        name: "CUser::BuildSpawnEnvBlock",
        label: "CUser::BuildSpawnEnvBlock body",
        validate: validate_build_spawn_env_block32,
    },
    SemanticCheck {
        name: "SetEnvString",
        label: "SetEnvString body",
        validate: validate_set_env_string32,
    },
];

const STEAMCLIENT64_SEMANTIC_CHECKS: &[SemanticCheck] = &[
    SemanticCheck {
        name: "CUser::CheckAppOwnership",
        label: "CUser::CheckAppOwnership body",
        validate: validate_check_app_ownership64,
    },
    SemanticCheck {
        name: "CUser::GetSubscribedApps",
        label: "CUser::GetSubscribedApps body",
        validate: validate_get_subscribed_apps64,
    },
    SemanticCheck {
        name: "CSteamEngine::Init",
        label: "CSteamEngine::Init body",
        validate: validate_steam_engine_init64,
    },
    SemanticCheck {
        name: "CSteamEngine::SetAPICallResult",
        label: "CSteamEngine::SetAPICallResult body",
        validate: validate_set_api_call_result64,
    },
    SemanticCheck {
        name: "IClientRemoteStorage::RunIPCFrame",
        label: "IClientRemoteStorage::RunIPCFrame body",
        validate: validate_ipc_run_frame64,
    },
    SemanticCheck {
        name: "IClientAppManager::RunIPCFrame",
        label: "IClientAppManager::RunIPCFrame body",
        validate: validate_ipc_run_frame64,
    },
    SemanticCheck {
        name: "IClientApps::RunIPCFrame",
        label: "IClientApps::RunIPCFrame body",
        validate: validate_ipc_run_frame64,
    },
    SemanticCheck {
        name: "LoadDepotDecryptionKey",
        label: "LoadDepotDecryptionKey body",
        validate: validate_load_depot_key64,
    },
    SemanticCheck {
        name: "BuildDepotDependency",
        label: "BuildDepotDependency body",
        validate: validate_build_depot_dependency64,
    },
    SemanticCheck {
        name: "CWebSocketConnection::BBuildAndAsyncSendFrame",
        label: "CWebSocketConnection::BBuildAndAsyncSendFrame body",
        validate: validate_websocket_send_frame64,
    },
    SemanticCheck {
        name: "CCMConnection::RecvPkt",
        label: "CCMConnection::RecvPkt body",
        validate: validate_ccm_recv_pkt64,
    },
    SemanticCheck {
        name: "CHTTPRequestJob::Start",
        label: "CHTTPRequestJob::Start body",
        validate: validate_http_request_job_start64,
    },
    SemanticCheck {
        name: "CUser::MarkLicenseAsChanged",
        label: "CUser::MarkLicenseAsChanged body",
        validate: validate_mark_license_changed64,
    },
    SemanticCheck {
        name: "CUser::ProcessPendingLicenseUpdates",
        label: "CUser::ProcessPendingLicenseUpdates body",
        validate: validate_process_pending_license_updates64,
    },
    SemanticCheck {
        name: "CUtlMemory::Grow",
        label: "CUtlMemory::Grow body",
        validate: validate_cutl_memory_grow64,
    },
    SemanticCheck {
        name: "CConfigStore::WriteVdfFile",
        label: "CConfigStore::WriteVdfFile body",
        validate: validate_write_vdf_file64,
    },
    SemanticCheck {
        name: "CUser::SpawnProcess",
        label: "CUser::SpawnProcess body",
        validate: validate_spawn_process64,
    },
    SemanticCheck {
        name: "CUser::BuildSpawnEnvBlock",
        label: "CUser::BuildSpawnEnvBlock body",
        validate: validate_build_spawn_env_block64,
    },
    SemanticCheck {
        name: "SetEnvString",
        label: "SetEnvString body",
        validate: validate_set_env_string64,
    },
];

const STEAMUI32_SEMANTIC_CHECKS: &[SemanticCheck] = &[
    SemanticCheck {
        name: "CSteamUIAppController::RunFrame",
        label: "CSteamUIAppController::RunFrame body",
        validate: validate_steamui_run_frame32,
    },
    SemanticCheck {
        name: "CSteamUIAppController::FillInAppOverview",
        label: "CSteamUIAppController::FillInAppOverview body",
        validate: validate_fill_in_app_overview32,
    },
    SemanticCheck {
        name: "CSteamUIAppController::BuildCompleteAppOverviewChange",
        label: "CSteamUIAppController::BuildCompleteAppOverviewChange body",
        validate: validate_build_complete_app_overview_change32,
    },
    SemanticCheck {
        name: "CSteamUIAppController::GetAppByID",
        label: "CSteamUIAppController::GetAppByID body",
        validate: validate_get_app_by_id32,
    },
    SemanticCheck {
        name: "CUpdateManager::MarkAppChange",
        label: "CUpdateManager::MarkAppChange body",
        validate: validate_mark_app_change32,
    },
    SemanticCheck {
        name: "google::protobuf::RepeatedField<uint32>::Add",
        label: "google::protobuf::RepeatedField<uint32>::Add body",
        validate: validate_repeated_field_add32,
    },
];

const STEAMUI64_SEMANTIC_CHECKS: &[SemanticCheck] = &[
    SemanticCheck {
        name: "CSteamUIAppController::RunFrame",
        label: "CSteamUIAppController::RunFrame body",
        validate: validate_steamui_run_frame64,
    },
    SemanticCheck {
        name: "CSteamUIAppController::FillInAppOverview",
        label: "CSteamUIAppController::FillInAppOverview body",
        validate: validate_fill_in_app_overview64,
    },
    SemanticCheck {
        name: "CSteamUIAppController::BuildCompleteAppOverviewChange",
        label: "CSteamUIAppController::BuildCompleteAppOverviewChange body",
        validate: validate_build_complete_app_overview_change64,
    },
    SemanticCheck {
        name: "CSteamUIAppController::GetAppByID",
        label: "CSteamUIAppController::GetAppByID body",
        validate: validate_get_app_by_id64,
    },
    SemanticCheck {
        name: "CUpdateManager::MarkAppChange",
        label: "CUpdateManager::MarkAppChange body",
        validate: validate_mark_app_change64,
    },
    SemanticCheck {
        name: "google::protobuf::RepeatedField<uint32>::Add",
        label: "google::protobuf::RepeatedField<uint32>::Add body",
        validate: validate_repeated_field_add64,
    },
];

const STEAMCLIENT_SPECIAL_SEMANTIC_CHECKS: &[&str] = &[
    "CConfigStore::ClientIDConfigAccess",
    "CPackageInfo::GetPackageInfo",
];

fn has_semantic_validation(module: &str, arch: SemanticArch, name: &str) -> bool {
    let checks = match (module, arch) {
        ("steamclient", SemanticArch::X86) => STEAMCLIENT32_SEMANTIC_CHECKS,
        ("steamclient", SemanticArch::X86_64) => STEAMCLIENT64_SEMANTIC_CHECKS,
        ("steamui", SemanticArch::X86) => STEAMUI32_SEMANTIC_CHECKS,
        ("steamui", SemanticArch::X86_64) => STEAMUI64_SEMANTIC_CHECKS,
        _ => &[],
    };

    checks.iter().any(|check| check.name == name)
        || (module == "steamclient" && STEAMCLIENT_SPECIAL_SEMANTIC_CHECKS.contains(&name))
}

fn scan_semantic_coverage(module: &str, arch: SemanticArch, entries: &[&ScanEntry]) -> bool {
    let mut failed = false;
    for group in group_scan_entries(entries) {
        let entry = group[0];
        if !has_semantic_validation(module, arch, &entry.name) {
            println!(
                "  FAIL {:<58} required (no semantic validation registered)",
                entry.name
            );
            failed = true;
        }
    }
    failed
}

fn scan_semantic_checks(
    code: &[u8],
    vaddr: u64,
    resolved: &HashMap<&str, usize>,
    checks: &[SemanticCheck],
    arch: SemanticArch,
) -> bool {
    let mut failed = false;
    for check in checks {
        let Some(&offset) = resolved.get(check.name) else {
            continue;
        };
        match (check.validate)(code, offset) {
            Some(detail) => println!("  OK   {:<58} {}", check.label, detail),
            None => {
                let detail = semantic_failure_evidence(arch, check.name, code, offset)
                    .map(|evidence| evidence.describe())
                    .unwrap_or_else(|| "semantic validation failed".to_owned());
                println!(
                    "  FAIL {:<58} va=0x{:x} required ({})",
                    check.label,
                    vaddr + offset as u64,
                    detail
                );
                failed = true;
            }
        }
    }
    failed
}

fn print_evidence_failure(
    label: &str,
    vaddr: u64,
    evidence: Option<&Evidence>,
    fallback: &'static str,
) {
    let detail = evidence
        .map(Evidence::describe)
        .unwrap_or_else(|| fallback.to_owned());
    println!(
        "  FAIL {:<58} va=0x{:x} required ({})",
        label, vaddr, detail
    );
}

const CLIENT_ID_ACCESS_NAME: &str = "CConfigStore::ClientIDConfigAccess";
const CLIENT_ID_STREAMING_KEY: &str = "streaming/ClientID";
const CLIENT_ID_SITE_LICENSE_KEY: &str = "sitelicense/ClientID";
const CONFIG_GET_UINT64_SLOT: usize = 3;
const CONFIG_SET_UINT64_SLOT: usize = 11;

#[derive(Clone, Copy, Debug)]
enum ClientIdKeyReference32 {
    Direct(i32),
    Indirect(i32),
}

#[derive(Debug)]
struct ClientIdAccess32 {
    pic_register: iced_x86::Register,
    root_displacement: i32,
    store_offset: u64,
    key_references: Vec<(iced_x86::Register, ClientIdKeyReference32)>,
    key_argument: iced_x86::Register,
}

#[derive(Debug)]
struct ClientIdBehavior {
    root_slot_va: u64,
    store_offset: u64,
    streaming_key_va: u64,
    site_license_key_va: u64,
    key_addressing: &'static str,
}

#[derive(Clone, Copy, Debug)]
enum StackArgument {
    Register(iced_x86::Register),
    Immediate(u64),
}

fn scan_client_id_config_behavior(
    path: &Path,
    data: &[u8],
    segment: ExecutableSegment<'_>,
    resolved: &HashMap<&str, usize>,
) -> bool {
    let Some(&candidate_offset) = resolved.get(CLIENT_ID_ACCESS_NAME) else {
        return false;
    };
    let image = match ElfImage::parse(data) {
        Ok(image) => image,
        Err(error) => {
            println!("  FAIL {:<58} {}", "ClientID config behavior", error);
            return true;
        }
    };
    let candidate_va = segment.vaddr + candidate_offset as u64;
    let behavior = match image.class {
        ElfClass::Elf32 => {
            validate_client_id_behavior32(&image, &segment, candidate_offset)
        }
        ElfClass::Elf64 => {
            validate_client_id_behavior64(&image, &segment, candidate_offset)
        }
    };
    let behavior = match behavior {
        Ok(behavior) => behavior,
        Err(error) => {
            println!(
                "  FAIL {:<58} va=0x{:x} required ({})",
                "ClientID config behavior", candidate_va, error
            );
            return true;
        }
    };
    let (getter_va, setter_va) = match validate_config_store_vtable(path) {
        Ok(methods) => methods,
        Err(error) => {
            println!(
                "  FAIL {:<58} va=0x{:x} required ({})",
                "ClientID config getter/setter", candidate_va, error
            );
            return true;
        }
    };

    println!(
        "  OK   {:<58} arch={} candidate=0x{:x} root=0x{:x} store=0x{:x} keys=0x{:x}/0x{:x} key_mode={}",
        "ClientID config behavior",
        image.class.label(),
        candidate_va,
        behavior.root_slot_va,
        behavior.store_offset,
        behavior.streaming_key_va,
        behavior.site_license_key_va,
        behavior.key_addressing,
    );
    println!(
        "  OK   {:<58} GetUint64=slot{}@0x{:x} SetUint64=slot{}@0x{:x} store=InstallConfigStore",
        "ClientID config getter/setter",
        CONFIG_GET_UINT64_SLOT,
        getter_va,
        CONFIG_SET_UINT64_SLOT,
        setter_va,
    );
    false
}

fn validate_config_store_vtable(path: &Path) -> Result<(u64, u64), String> {
    let wanted = vec!["IClientConfigStore".to_owned()];
    let report = vtable_scan::scan_file(path, Some(&wanted))?;
    let interface = report
        .interfaces
        .iter()
        .find(|interface| interface.name == "IClientConfigStore")
        .ok_or_else(|| "IClientConfigStore vtable was not found".to_owned())?;
    let getter = interface
        .methods
        .get(CONFIG_GET_UINT64_SLOT)
        .filter(|method| method.name == "GetUint64")
        .ok_or_else(|| "slot 3 is not IClientConfigStore::GetUint64".to_owned())?;
    let setter = interface
        .methods
        .get(CONFIG_SET_UINT64_SLOT)
        .filter(|method| method.name == "SetUint64")
        .ok_or_else(|| "slot 11 is not IClientConfigStore::SetUint64".to_owned())?;
    Ok((getter.func_va, setter.func_va))
}

const USER_STATS_WRAPPER_METHODS: &[&str] = &[
    "GetNumAchievements",
    "GetAchievementName",
    "RequestCurrentStats",
    "GetAchievement",
    "SetAchievement",
    "ClearAchievement",
    "StoreStats",
    "IndicateAchievementProgress",
];

fn scan_user_stats_wrapper_abi(path: &Path, data: &[u8]) -> bool {
    let image = match ElfImage::parse(data) {
        Ok(image) => image,
        Err(error) => {
            println!(
                "  FAIL {:<58} required ({error})",
                "IClientUserStats wrapper CGameID ABI"
            );
            return true;
        }
    };
    let wanted = vec!["IClientUserStats".to_owned()];
    let report = match vtable_scan::scan_file(path, Some(&wanted)) {
        Ok(report) => report,
        Err(error) => {
            println!(
                "  FAIL {:<58} required ({error})",
                "IClientUserStats wrapper CGameID ABI"
            );
            return true;
        }
    };
    let Some(interface) = report
        .interfaces
        .iter()
        .find(|interface| interface.name == "IClientUserStats")
    else {
        println!(
            "  FAIL {:<58} required (vtable was not found)",
            "IClientUserStats wrapper CGameID ABI"
        );
        return true;
    };

    for &name in USER_STATS_WRAPPER_METHODS {
        let Some(method) = interface.methods.iter().find(|method| method.name == name) else {
            println!(
                "  FAIL {:<58} required ({name} wrapper was not found)",
                "IClientUserStats wrapper CGameID ABI"
            );
            return true;
        };
        let Some(offset) = image.va_to_offset(method.func_va) else {
            println!(
                "  FAIL {:<58} required ({name} wrapper is outside the file image)",
                "IClientUserStats wrapper CGameID ABI"
            );
            return true;
        };
        let bytes = &data[offset..data.len().min(offset.saturating_add(0x100))];
        if !wrapper_dereferences_game_id(bytes, image.class) {
            println!(
                "  FAIL {:<58} slot={} required ({name} does not dereference CGameID argument)",
                "IClientUserStats wrapper CGameID ABI", method.slot
            );
            return true;
        }
    }

    println!(
        "  OK   {:<58} methods={} argument=const CGameID&",
        "IClientUserStats wrapper CGameID ABI",
        USER_STATS_WRAPPER_METHODS.len()
    );
    false
}

fn wrapper_dereferences_game_id(bytes: &[u8], class: ElfClass) -> bool {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};

    let mut decoder = Decoder::with_ip(class.bits().into(), bytes, 0, DecoderOptions::NONE);
    let mut aliases = std::collections::HashSet::new();
    let mut frame_aliases = std::collections::HashSet::new();
    if class == ElfClass::Elf64 {
        aliases.insert(Register::RSI);
    }

    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        let memory_source = instruction.op1_kind() == OpKind::Memory;
        if memory_source
            && instruction.memory_displacement64() == 0
            && aliases.contains(&instruction.memory_base())
        {
            return true;
        }

        if class == ElfClass::Elf32
            && instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && memory_source
            && instruction.memory_base() == Register::EBP
            && instruction.memory_displacement64() == 0x0c
        {
            aliases.insert(instruction.op0_register());
            continue;
        }

        let frame_slot = || {
            (instruction.memory_base() == Register::EBP
                || instruction.memory_base() == Register::RBP)
                .then_some(instruction.memory_displacement64())
        };
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Memory
            && instruction.op1_kind() == OpKind::Register
        {
            if let Some(slot) = frame_slot() {
                if aliases.contains(&instruction.op1_register()) {
                    frame_aliases.insert(slot);
                } else {
                    frame_aliases.remove(&slot);
                }
            }
        }

        if instruction.mnemonic() == Mnemonic::Mov && instruction.op0_kind() == OpKind::Register {
            let destination = instruction.op0_register();
            let copies_alias = instruction.op1_kind() == OpKind::Register
                && aliases.contains(&instruction.op1_register());
            let restores_alias = memory_source
                && frame_slot().is_some_and(|slot| frame_aliases.contains(&slot));
            if copies_alias || restores_alias {
                aliases.insert(destination);
            } else {
                aliases.remove(&destination);
            }
        }
    }
    false
}

fn scan_cuser_stats_adapters(
    path: &Path,
    code: &[u8],
    text_vaddr: u64,
    arch: SemanticArch,
) -> bool {
    let wanted = vec!["IClientUserStats".to_owned(), "CUserStats".to_owned()];
    let report = match vtable_scan::scan_file(path, Some(&wanted)) {
        Ok(report) => report,
        Err(error) => {
            println!("  FAIL {:<58} required ({error})", "CUserStats vtable adapters");
            return true;
        }
    };
    let Some(public) = report
        .interfaces
        .iter()
        .find(|interface| interface.name == "IClientUserStats")
    else {
        println!(
            "  FAIL {:<58} required (IClientUserStats vtable was not found)",
            "CUserStats vtable adapters"
        );
        return true;
    };
    let Some(service) = report
        .interfaces
        .iter()
        .find(|interface| interface.name == "CUserStats")
    else {
        println!(
            "  FAIL {:<58} required (CUserStats primary vtable was not found)",
            "CUserStats vtable adapters"
        );
        return true;
    };

    let set_stat_slots = public
        .methods
        .iter()
        .filter(|method| method.name == "SetStat")
        .map(|method| method.slot)
        .collect::<Vec<_>>();
    if set_stat_slots.len() != 2 {
        println!(
            "  FAIL {:<58} required (expected two SetStat overloads, found {})",
            "CUserStats vtable adapters",
            set_stat_slots.len()
        );
        return true;
    }

    let named_slot = |name: &str| {
        public
            .methods
            .iter()
            .find(|method| method.name == name)
            .map(|method| method.slot)
    };
    let Some(set_achievement_slot) = named_slot("SetAchievement") else {
        return print_missing_user_stats_slot("SetAchievement");
    };
    let Some(clear_achievement_slot) = named_slot("ClearAchievement") else {
        return print_missing_user_stats_slot("ClearAchievement");
    };
    let Some(store_stats_slot) = named_slot("StoreStats") else {
        return print_missing_user_stats_slot("StoreStats");
    };
    let Some(progress_slot) = named_slot("IndicateAchievementProgress") else {
        return print_missing_user_stats_slot("IndicateAchievementProgress");
    };

    /// Collects the evidence for one adapter body at a given offset.
    type EvidenceFn = fn(&[u8], usize) -> Option<Evidence>;

    let specs: [(&str, usize, EvidenceFn); 6] = match arch {
        SemanticArch::X86 => [
            ("SetStat(int32)", set_stat_slots[0], |code, offset| {
                set_stat_adapter32_evidence(code, offset, 0xe4)
            }),
            ("SetStat(float)", set_stat_slots[1], |code, offset| {
                set_stat_adapter32_evidence(code, offset, 0xe8)
            }),
            (
                "SetAchievement",
                set_achievement_slot,
                |code, offset| named_achievement_adapter32_evidence(code, offset, 0xf0),
            ),
            (
                "ClearAchievement",
                clear_achievement_slot,
                |code, offset| named_achievement_adapter32_evidence(code, offset, 0xf4),
            ),
            ("StoreStats", store_stats_slot, store_stats_adapter32_evidence),
            (
                "IndicateAchievementProgress",
                progress_slot,
                achievement_progress_adapter32_evidence,
            ),
        ],
        SemanticArch::X86_64 => [
            ("SetStat(int32)", set_stat_slots[0], set_stat_int_adapter64_evidence),
            ("SetStat(float)", set_stat_slots[1], set_stat_float_adapter64_evidence),
            (
                "SetAchievement",
                set_achievement_slot,
                set_achievement_adapter64_evidence,
            ),
            (
                "ClearAchievement",
                clear_achievement_slot,
                clear_achievement_adapter64_evidence,
            ),
            ("StoreStats", store_stats_slot, store_stats_adapter64_evidence),
            (
                "IndicateAchievementProgress",
                progress_slot,
                achievement_progress_adapter64_evidence,
            ),
        ],
    };

    let mut failed = false;
    for (name, slot, validate) in specs {
        let Some(method) = service.methods.get(slot) else {
            println!(
                "  FAIL {:<58} slot={} required (slot is outside CUserStats vtable)",
                format!("CUserStats::{name} adapter"),
                slot
            );
            failed = true;
            continue;
        };
        let Some(offset) = method.func_va.checked_sub(text_vaddr).map(|offset| offset as usize)
        else {
            failed = true;
            continue;
        };
        let evidence = validate(code, offset);
        if evidence.as_ref().is_some_and(Evidence::is_complete) {
            println!(
                "  OK   {:<58} slot={} va=0x{:x}",
                format!("CUserStats::{name} adapter"),
                slot,
                method.func_va
            );
        } else {
            print_evidence_failure(
                &format!("CUserStats::{name} adapter"),
                method.func_va,
                evidence.as_ref(),
                "semantic validation failed",
            );
            failed = true;
        }
    }
    failed
}

fn print_missing_user_stats_slot(name: &str) -> bool {
    println!(
        "  FAIL {:<58} required (IClientUserStats::{name} was not found)",
        "CUserStats vtable adapters"
    );
    true
}

#[derive(Clone, Copy)]
enum CUserAdapterKind {
    TicketExtendedData,
    UpdateTicket,
    IsSubscribedInTicket,
}

fn scan_cuser_adapters(
    path: &Path,
    code: &[u8],
    text_vaddr: u64,
    arch: SemanticArch,
    resolved: &HashMap<&str, usize>,
) -> bool {
    let wanted = vec!["IClientUser".to_owned()];
    let public_report = match vtable_scan::scan_file(path, Some(&wanted)) {
        Ok(report) => report,
        Err(error) => {
            println!("  FAIL {:<58} required ({error})", "CUser vtable adapters");
            return true;
        }
    };
    let Some(public) = public_report
        .interfaces
        .iter()
        .find(|interface| interface.name == "IClientUser")
    else {
        println!(
            "  FAIL {:<58} required (IClientUser vtable was not found)",
            "CUser vtable adapters"
        );
        return true;
    };
    let class_vtables = match vtable_scan::scan_class_vtables(path, "CUser") {
        Ok(vtables) if !vtables.is_empty() => vtables,
        Ok(_) => {
            println!(
                "  FAIL {:<58} required (CUser vtables were not found)",
                "CUser vtable adapters"
            );
            return true;
        }
        Err(error) => {
            println!("  FAIL {:<58} required ({error})", "CUser vtable adapters");
            return true;
        }
    };
    let specs = [
        (
            "GetAppOwnershipTicketExtendedData",
            CUserAdapterKind::TicketExtendedData,
        ),
        (
            "BUpdateAppOwnershipTicket",
            CUserAdapterKind::UpdateTicket,
        ),
        (
            "IsUserSubscribedAppInTicket",
            CUserAdapterKind::IsSubscribedInTicket,
        ),
    ];

    let mut failed = false;
    for (name, kind) in specs {
        let slots = public
            .methods
            .iter()
            .filter(|method| method.name == name)
            .map(|method| method.slot)
            .collect::<Vec<_>>();
        if slots.len() != 1 {
            println!(
                "  FAIL {:<58} required (expected one IClientUser slot, found {})",
                format!("CUser::{name} adapter"),
                slots.len()
            );
            failed = true;
            continue;
        }
        let public_slot = slots[0];
        let iface_slot_count = public.methods.len();
        // Pick the CUser secondary vtable whose slot count matches the
        // IClientUser interface width, then take its entry at public_slot.
        let mut matches = class_vtables
            .iter()
            .filter(|vtable| vtable.offset_to_top < 0)
            .filter(|vtable| vtable.methods.len() == iface_slot_count)
            .flat_map(|vtable| {
                vtable.methods.iter().filter_map(|method| {
                    if method.slot != public_slot {
                        return None;
                    }
                    let offset = method.func_va.checked_sub(text_vaddr)? as usize;
                    let implementation = resolve_cuser_adapter_implementation(
                        code,
                        text_vaddr,
                        offset,
                        kind,
                        arch,
                        resolved,
                    )
                    .unwrap_or(offset);
                    Some((
                        method.func_va,
                        vtable.offset_to_top,
                        method.slot,
                        offset,
                        implementation,
                    ))
                })
            })
            .collect::<Vec<_>>();
        matches.sort_by_key(|candidate| candidate.4);
        matches.dedup_by_key(|candidate| candidate.4);
        if matches.len() != 1 {
            println!(
                "  FAIL {:<58} public-slot={} required (validated entries={})",
                format!("CUser::{name} adapter"),
                public_slot,
                matches.len()
            );
            for (func_va, offset_to_top, service_slot, _, implementation) in &matches {
                println!(
                    "       validated entry service-slot={} adapter=0x{:x} target=0x{:x} offset-to-top={:#x}",
                    service_slot,
                    func_va,
                    text_vaddr + *implementation as u64,
                    offset_to_top
                );
            }
            failed = true;
            continue;
        }
        let (func_va, offset_to_top, service_slot, _, implementation) = matches[0];
        println!(
            "  OK   {:<58} public-slot={} service-slot={} adapter=0x{:x} target=0x{:x} offset-to-top={:#x}",
            format!("CUser::{name} adapter"),
            public_slot,
            service_slot,
            func_va,
            text_vaddr + implementation as u64,
            offset_to_top
        );
    }
    failed
}

fn resolve_cuser_adapter_implementation(
    code: &[u8],
    text_vaddr: u64,
    offset: usize,
    kind: CUserAdapterKind,
    arch: SemanticArch,
    resolved: &HashMap<&str, usize>,
) -> Option<usize> {
    if matches!(kind, CUserAdapterKind::IsSubscribedInTicket)
        && !validate_is_subscribed_wrapper_abi(code, offset, arch)
    {
        return None;
    }
    if !matches!(kind, CUserAdapterKind::IsSubscribedInTicket)
        && validate_cuser_adapter_direct(code, text_vaddr, offset, kind, arch, resolved)
    {
        return Some(offset);
    }
    let mut targets = direct_branch_target_offsets(code, text_vaddr, offset, 0x180, arch)
        .into_iter()
        .filter(|&target| {
            validate_cuser_adapter_direct(code, text_vaddr, target, kind, arch, resolved)
        })
        .collect::<Vec<_>>();
    targets.sort_unstable();
    targets.dedup();
    if targets.len() == 1 {
        targets.first().copied()
    } else {
        None
    }
}

fn validate_is_subscribed_wrapper_abi(
    code: &[u8],
    offset: usize,
    arch: SemanticArch,
) -> bool {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};

    let Some(bytes) = code.get(offset..code.len().min(offset.saturating_add(0x180))) else {
        return false;
    };
    if arch == SemanticArch::X86 {
        let adjusts_this = has_seq(bytes, &[0x81, 0xee, 0xd4, 0x18, 0x00, 0x00])
            || has_seq(bytes, &[0x2d, 0xd4, 0x18, 0x00, 0x00])
            || has_seq(bytes, &[0x2d, 0xd8, 0x18, 0x00, 0x00]);
        return adjusts_this
            && bytes
                .windows(4)
                .any(|window| window[0..3] == [0x8d, 0x44, 0x24]);
    }

    let mut decoder = Decoder::with_ip(64, bytes, offset as u64, DecoderOptions::NONE);
    let mut app_id_aliases = std::collections::HashSet::from([Register::EDX]);
    let mut forwards_app_id = false;
    let mut constructs_game_id = false;
    let mut adjusts_this = false;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        if instruction.mnemonic() == Mnemonic::Mov && instruction.op0_kind() == OpKind::Register {
            let destination = instruction.op0_register();
            if instruction.op1_kind() == OpKind::Register
                && app_id_aliases.contains(&instruction.op1_register())
            {
                app_id_aliases.insert(destination);
            } else if destination != Register::ECX {
                app_id_aliases.remove(&destination);
            }
            if destination == Register::ECX
                && instruction.op1_kind() == OpKind::Register
                && app_id_aliases.contains(&instruction.op1_register())
            {
                forwards_app_id = true;
            }
        }
        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_register() == Register::RDX
            && instruction.memory_base() == Register::RSP
        {
            constructs_game_id = true;
        }
        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_register() == Register::RDI
            && instruction.memory_displacement64() as i64 == -0x1fd0
        {
            adjusts_this = true;
        }
    }
    forwards_app_id && constructs_game_id && adjusts_this
}

fn validate_cuser_adapter_direct(
    code: &[u8],
    text_vaddr: u64,
    offset: usize,
    kind: CUserAdapterKind,
    arch: SemanticArch,
    resolved: &HashMap<&str, usize>,
) -> bool {
    validate_cuser_adapter(code, offset, kind, arch, resolved)
        && (!matches!(kind, CUserAdapterKind::TicketExtendedData)
            || ticket_ext_semantics_are_reachable(code, text_vaddr, offset, arch))
}

fn validate_cuser_adapter(
    code: &[u8],
    offset: usize,
    kind: CUserAdapterKind,
    arch: SemanticArch,
    resolved: &HashMap<&str, usize>,
) -> bool {
    let evidence = match (arch, kind) {
        (SemanticArch::X86, CUserAdapterKind::TicketExtendedData) => {
            ticket_ext_data_mode4_thunk32_evidence(code, offset)
        }
        (SemanticArch::X86_64, CUserAdapterKind::TicketExtendedData) => {
            ticket_ext_data_mode4_thunk64_evidence(code, offset)
        }
        (SemanticArch::X86, CUserAdapterKind::UpdateTicket) => resolved
            .get("CUser::CheckAppOwnership")
            .and_then(|check| update_ticket32_evidence(code, offset, *check)),
        (SemanticArch::X86_64, CUserAdapterKind::UpdateTicket) => resolved
            .get("CUser::CheckAppOwnership")
            .and_then(|check| update_ticket64_evidence(code, offset, *check)),
        (SemanticArch::X86, CUserAdapterKind::IsSubscribedInTicket) => {
            is_user_subscribed_app_in_ticket32_evidence(code, offset)
        }
        (SemanticArch::X86_64, CUserAdapterKind::IsSubscribedInTicket) => {
            is_user_subscribed_app_in_ticket64_evidence(code, offset)
        }
    };
    evidence.is_some_and(|evidence| evidence.is_complete())
}

fn direct_branch_target_offsets(
    code: &[u8],
    text_vaddr: u64,
    offset: usize,
    max_len: usize,
    arch: SemanticArch,
) -> Vec<usize> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl};

    let Some(bytes) = code.get(offset..code.len().min(offset.saturating_add(max_len))) else {
        return Vec::new();
    };
    let bitness = match arch {
        SemanticArch::X86 => 32,
        SemanticArch::X86_64 => 64,
    };
    let mut decoder = Decoder::with_ip(
        bitness,
        bytes,
        text_vaddr + offset as u64,
        DecoderOptions::NONE,
    );
    let mut targets = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        if matches!(
            instruction.flow_control(),
            FlowControl::Call | FlowControl::UnconditionalBranch
        ) {
            let target = instruction.near_branch_target();
            if let Some(offset) = target
                .checked_sub(text_vaddr)
                .and_then(|offset| usize::try_from(offset).ok())
                .filter(|&offset| offset < code.len())
            {
                targets.push(offset);
            }
        }
        if matches!(
            instruction.flow_control(),
            FlowControl::Return | FlowControl::UnconditionalBranch
        ) {
            break;
        }
    }
    targets
}

fn ticket_ext_semantics_are_reachable(
    code: &[u8],
    text_vaddr: u64,
    offset: usize,
    arch: SemanticArch,
) -> bool {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};

    let Some(bytes) = code.get(offset..code.len().min(offset.saturating_add(0x160))) else {
        return false;
    };
    let adjustments: &[&[u8]] = match arch {
        SemanticArch::X86 => &[
            &[0x2d, 0xd4, 0x18, 0x00, 0x00],
            &[0x2d, 0xd8, 0x18, 0x00, 0x00],
        ],
        SemanticArch::X86_64 => &[
            &[0x49, 0x8d, 0xbc, 0x24, 0x30, 0xe0, 0xff, 0xff],
            &[0x48, 0x8d, 0xbb, 0x30, 0xe0, 0xff, 0xff],
        ],
    };
    let reachable = reachable_instruction_offsets(
        bytes,
        text_vaddr + offset as u64,
        match arch {
            SemanticArch::X86 => 32,
            SemanticArch::X86_64 => 64,
        },
    );
    let has_adjustment = adjustments.iter().any(|needle| {
        bytes
            .windows(needle.len())
            .enumerate()
            .any(|(index, window)| window == *needle && reachable.contains(&index))
    });
    let bitness = match arch {
        SemanticArch::X86 => 32,
        SemanticArch::X86_64 => 64,
    };
    let mut has_mode4 = false;
    let mut has_call_after_mode4 = false;
    let mut has_high_stack_argument = false;
    let mut register_self_tests = 0usize;
    for &instruction_offset in &reachable {
        let mut decoder = Decoder::with_ip(
            bitness,
            &bytes[instruction_offset..],
            text_vaddr + offset as u64 + instruction_offset as u64,
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            continue;
        }
        if bytes.get(instruction_offset..instruction_offset + 2) == Some(&[0x6a, 0x04]) {
            has_mode4 = true;
        }
        if instruction.flow_control() == FlowControl::Call
            && reachable.iter().any(|&push| {
                bytes.get(push..push + 2) == Some(&[0x6a, 0x04])
                    && instruction_offset > push
                    && instruction_offset <= push + 0x30
            })
        {
            has_call_after_mode4 = true;
        }
        if matches!(instruction.memory_base(), Register::RSP | Register::ESP) {
            has_high_stack_argument |=
                (0x30..=0x100).contains(&(instruction.memory_displacement64() as usize));
        }
        if instruction.mnemonic() == Mnemonic::Test
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Register
            && instruction.op0_register() == instruction.op1_register()
        {
            register_self_tests += 1;
        }
    }
    has_adjustment
        && has_mode4
        && has_call_after_mode4
        && has_high_stack_argument
        && register_self_tests >= 2
}

fn reachable_instruction_offsets(
    bytes: &[u8],
    ip: u64,
    bitness: u32,
) -> std::collections::HashSet<usize> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl};

    let mut pending = vec![0usize];
    let mut reachable = std::collections::HashSet::new();
    while let Some(offset) = pending.pop() {
        if offset >= bytes.len() || !reachable.insert(offset) {
            continue;
        }
        let mut decoder = Decoder::with_ip(
            bitness,
            &bytes[offset..],
            ip + offset as u64,
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            continue;
        }
        let next = offset.saturating_add(instruction.len());
        let branch_offset = instruction
            .near_branch_target()
            .checked_sub(ip)
            .and_then(|target| usize::try_from(target).ok())
            .filter(|&target| target < bytes.len());
        match instruction.flow_control() {
            FlowControl::Return | FlowControl::IndirectBranch => {}
            FlowControl::UnconditionalBranch => {
                if let Some(target) = branch_offset {
                    pending.push(target);
                }
            }
            FlowControl::ConditionalBranch => {
                pending.push(next);
                if let Some(target) = branch_offset {
                    pending.push(target);
                }
            }
            _ => pending.push(next),
        }
    }
    reachable
}

fn validate_client_id_behavior32(
    image: &ElfImage<'_>,
    segment: &ExecutableSegment<'_>,
    candidate_offset: usize,
) -> Result<ClientIdBehavior, String> {
    let access = parse_client_id_access32(segment, candidate_offset)
        .ok_or_else(|| "candidate does not contain the x86 CConfigStore setter flow".to_owned())?;
    let pic_anchor = find_pic_anchor32(image, segment, candidate_offset, access.pic_register)
        .ok_or_else(|| "matching __x86.get_pc_thunk/add PIC anchor was not found".to_owned())?;
    let root_slot_va = add_x86_displacement(pic_anchor, access.root_displacement);
    if !image.in_module(root_slot_va) || image.in_text(root_slot_va) {
        return Err(format!(
            "PIC root slot 0x{root_slot_va:x} is not module data"
        ));
    }

    let mut streaming_key_va = None;
    let mut site_license_key_va = None;
    let mut saw_direct = false;
    let mut saw_indirect = false;
    let mut call_key_matches = false;
    for (register, reference) in access.key_references {
        let is_indirect = matches!(reference, ClientIdKeyReference32::Indirect(_));
        let key_va = match reference {
            ClientIdKeyReference32::Direct(displacement) => {
                add_x86_displacement(pic_anchor, displacement)
            }
            ClientIdKeyReference32::Indirect(displacement) => {
                let slot = add_x86_displacement(pic_anchor, displacement);
                image
                    .read_word_va(slot)
                    .ok_or_else(|| format!("PIC key slot 0x{slot:x} is unreadable"))?
            }
        };
        match image.read_cstring(key_va, 64).as_str() {
            CLIENT_ID_STREAMING_KEY => streaming_key_va = Some(key_va),
            CLIENT_ID_SITE_LICENSE_KEY => site_license_key_va = Some(key_va),
            _ => continue,
        }
        if is_indirect {
            saw_indirect = true;
        } else {
            saw_direct = true;
        }
        call_key_matches |= register == access.key_argument;
    }
    if !call_key_matches {
        return Err("SetUint64 key argument is not a resolved ClientID string".to_owned());
    }
    let key_addressing = match (saw_direct, saw_indirect) {
        (true, false) => "PIC-direct",
        (false, true) => "PIC-data-pointer",
        (true, true) => "PIC-mixed",
        (false, false) => return Err("no PIC ClientID key references were found".to_owned()),
    };
    Ok(ClientIdBehavior {
        root_slot_va,
        store_offset: access.store_offset,
        streaming_key_va: streaming_key_va
            .ok_or_else(|| "streaming/ClientID reference was not resolved".to_owned())?,
        site_license_key_va: site_license_key_va
            .ok_or_else(|| "sitelicense/ClientID reference was not resolved".to_owned())?,
        key_addressing,
    })
}

fn parse_client_id_access32(
    segment: &ExecutableSegment<'_>,
    candidate_offset: usize,
) -> Option<ClientIdAccess32> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};

    let bytes = segment
        .bytes
        .get(candidate_offset..candidate_offset.saturating_add(0xc0))?;
    let mut decoder = Decoder::with_ip(
        32,
        bytes,
        segment.vaddr + candidate_offset as u64,
        DecoderOptions::NONE,
    );
    let mut address_candidates = Vec::new();
    let mut root_register = None;
    let mut pic_register = None;
    let mut root_displacement = None;
    let mut store_register = None;
    let mut store_offset = None;
    let mut vtable_register = None;
    let mut setter_register = None;
    let mut key_references = Vec::new();
    let mut stack_arguments = Vec::new();
    let mut key_argument = None;

    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        if instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_kind() == OpKind::Register
            && instruction.memory_base() != Register::None
            && instruction.memory_index() == Register::None
        {
            address_candidates.push((
                instruction.op0_register(),
                instruction.memory_base(),
                instruction.memory_displacement32() as i32,
            ));
        }
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == instruction.memory_base()
            && instruction.memory_index() == Register::None
            && instruction.memory_displacement64() == 0
        {
            let register = instruction.op0_register();
            if let Some((_, base, displacement)) = address_candidates
                .iter()
                .rev()
                .find(|(destination, _, _)| *destination == register)
                .copied()
            {
                root_register = Some(register);
                pic_register = Some(base);
                root_displacement = Some(displacement);
            }
            continue;
        }
        if let Some(root) = root_register {
            if store_offset.is_none()
                && instruction.mnemonic() == Mnemonic::Lea
                && instruction.op0_kind() == OpKind::Register
                && instruction.memory_base() == root
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() <= 0x1_0000
            {
                store_register = Some(instruction.op0_register());
                store_offset = Some(instruction.memory_displacement64());
            }
        }
        if let (Some(root), Some(offset)) = (root_register, store_offset) {
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.memory_base() == root
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == offset
            {
                vtable_register = Some(instruction.op0_register());
            }
        }
        if let Some(vtable) = vtable_register {
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.memory_base() == vtable
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == (CONFIG_SET_UINT64_SLOT * 4) as u64
            {
                setter_register = Some(instruction.op0_register());
            }
        }
        if let Some(pic) = pic_register {
            if instruction.op0_kind() == OpKind::Register
                && instruction.memory_base() == pic
                && instruction.memory_index() == Register::None
            {
                let reference = match instruction.mnemonic() {
                    Mnemonic::Lea => Some(ClientIdKeyReference32::Direct(
                        instruction.memory_displacement32() as i32,
                    )),
                    Mnemonic::Mov => Some(ClientIdKeyReference32::Indirect(
                        instruction.memory_displacement32() as i32,
                    )),
                    _ => None,
                };
                if let Some(reference) = reference {
                    key_references.push((instruction.op0_register(), reference));
                }
            }
        }
        if instruction.mnemonic() == Mnemonic::Push {
            if instruction.op0_kind() == OpKind::Register {
                stack_arguments.push(StackArgument::Register(instruction.op0_register()));
            } else if let Some(immediate) = instruction_immediate(&instruction) {
                stack_arguments.push(StackArgument::Immediate(immediate));
            }
        }
        if setter_register.is_some_and(|setter| {
            instruction.flow_control() == FlowControl::IndirectCall
                && instruction.op0_kind() == OpKind::Register
                && instruction.op0_register() == setter
        }) {
            let args = stack_arguments.get(stack_arguments.len().checked_sub(5)?..)?;
            if !matches!(args[3], StackArgument::Immediate(1))
                || !matches!(args[4], StackArgument::Register(register) if Some(register) == store_register)
            {
                return None;
            }
            let StackArgument::Register(register) = args[2] else {
                return None;
            };
            key_argument = Some(register);
        }
    }

    Some(ClientIdAccess32 {
        pic_register: pic_register?,
        root_displacement: root_displacement?,
        store_offset: store_offset?,
        key_references,
        key_argument: key_argument?,
    })
}

fn instruction_immediate(instruction: &iced_x86::Instruction) -> Option<u64> {
    use iced_x86::OpKind;

    match instruction.op0_kind() {
        OpKind::Immediate8 => Some(u64::from(instruction.immediate8())),
        OpKind::Immediate8to16 => Some(instruction.immediate8to16() as u64),
        OpKind::Immediate8to32 => Some(instruction.immediate8to32() as u64),
        OpKind::Immediate8to64 => Some(instruction.immediate8to64() as u64),
        OpKind::Immediate16 => Some(u64::from(instruction.immediate16())),
        OpKind::Immediate32 => Some(u64::from(instruction.immediate32())),
        OpKind::Immediate32to64 => Some(instruction.immediate32to64() as u64),
        OpKind::Immediate64 => Some(instruction.immediate64()),
        _ => None,
    }
}

fn find_pic_anchor32(
    image: &ElfImage<'_>,
    segment: &ExecutableSegment<'_>,
    candidate_offset: usize,
    pic_register: iced_x86::Register,
) -> Option<u64> {
    let register_code = x86_register_code(pic_register)?;
    let start = candidate_offset.saturating_sub(0x200);
    for call_offset in (start..candidate_offset).rev() {
        if segment.bytes.get(call_offset) != Some(&0xe8) {
            continue;
        }
        let relative = i32::from_le_bytes(
            segment
                .bytes
                .get(call_offset + 1..call_offset + 5)?
                .try_into()
                .ok()?,
        );
        let after_call = segment.vaddr + call_offset as u64 + 5;
        let target = add_x86_displacement(after_call, relative);
        if image.read_u8_va(target) != Some(0x8b)
            || image
                .read_u8_va(target + 1)
                .map_or(true, |modrm| {
                    modrm & 0xc7 != 0x04 || (modrm >> 3) & 7 != register_code
                })
            || image.read_u8_va(target + 2) != Some(0x24)
            || image.read_u8_va(target + 3) != Some(0xc3)
        {
            continue;
        }
        let add_offset = call_offset + 5;
        let immediate = if register_code == 0 && segment.bytes.get(add_offset) == Some(&0x05) {
            u32::from_le_bytes(
                segment
                    .bytes
                    .get(add_offset + 1..add_offset + 5)?
                    .try_into()
                    .ok()?,
            )
        } else if segment.bytes.get(add_offset) == Some(&0x81)
            && segment.bytes.get(add_offset + 1) == Some(&(0xc0 | register_code))
        {
            u32::from_le_bytes(
                segment
                    .bytes
                    .get(add_offset + 2..add_offset + 6)?
                    .try_into()
                    .ok()?,
            )
        } else {
            continue;
        };
        return Some(u64::from((after_call as u32).wrapping_add(immediate)));
    }
    None
}

fn x86_register_code(register: iced_x86::Register) -> Option<u8> {
    use iced_x86::Register;

    match register {
        Register::EAX => Some(0),
        Register::ECX => Some(1),
        Register::EDX => Some(2),
        Register::EBX => Some(3),
        Register::ESP => Some(4),
        Register::EBP => Some(5),
        Register::ESI => Some(6),
        Register::EDI => Some(7),
        _ => None,
    }
}

fn add_x86_displacement(address: u64, displacement: i32) -> u64 {
    u64::from((address as u32).wrapping_add(displacement as u32))
}

fn validate_client_id_behavior64(
    image: &ElfImage<'_>,
    segment: &ExecutableSegment<'_>,
    candidate_offset: usize,
) -> Result<ClientIdBehavior, String> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};

    let bytes = segment
        .bytes
        .get(candidate_offset..candidate_offset.saturating_add(0xc0))
        .ok_or_else(|| "x86_64 candidate window is truncated".to_owned())?;
    let mut decoder = Decoder::with_ip(
        64,
        bytes,
        segment.vaddr + candidate_offset as u64,
        DecoderOptions::NONE,
    );
    let mut root_candidates = Vec::new();
    let mut root_register = None;
    let mut root_slot_va = None;
    let mut store_register = None;
    let mut store_offset = None;
    let mut vtable_register = None;
    let mut setter_register = None;
    let mut streaming_key_va = None;
    let mut site_license_key_va = None;
    let mut key_registers = Vec::new();
    let mut install_store = false;
    let mut setter_called = false;

    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        if instruction.is_ip_rel_memory_operand() && instruction.op0_kind() == OpKind::Register {
            let target = instruction.ip_rel_memory_address();
            let text = image.read_cstring(target, 64);
            if matches!(instruction.mnemonic(), Mnemonic::Lea | Mnemonic::Mov) {
                match text.as_str() {
                    CLIENT_ID_STREAMING_KEY => {
                        streaming_key_va = Some(target);
                        key_registers.push(instruction.op0_register());
                    }
                    CLIENT_ID_SITE_LICENSE_KEY => {
                        site_license_key_va = Some(target);
                        key_registers.push(instruction.op0_register());
                    }
                    _ if image.in_module(target) && !image.in_text(target) => {
                        root_candidates.push((
                            instruction.op0_register(),
                            target,
                            instruction.mnemonic() == Mnemonic::Mov,
                        ));
                    }
                    _ => {}
                }
            }
        }
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == instruction.memory_base()
            && instruction.memory_index() == Register::None
            && instruction.memory_displacement64() == 0
        {
            let register = instruction.op0_register();
            if let Some((_, slot, _)) = root_candidates
                .iter()
                .rev()
                .find(|(candidate, _, direct_load)| *candidate == register && !direct_load)
                .copied()
            {
                root_register = Some(register);
                root_slot_va = Some(slot);
            }
        }
        let memory_base = instruction.memory_base();
        let direct_root = root_candidates
            .iter()
            .rev()
            .find(|(register, _, direct_load)| *direct_load && *register == memory_base)
            .copied();
        if (root_register == Some(memory_base) || direct_root.is_some())
            && store_offset.is_none()
            && instruction.mnemonic() == Mnemonic::Lea
            && instruction.op0_kind() == OpKind::Register
            && instruction.memory_index() == Register::None
            && instruction.memory_displacement64() <= 0x1_0000
        {
            if let Some((register, slot, _)) = direct_root {
                root_register = Some(register);
                root_slot_va = Some(slot);
            }
            store_register = Some(instruction.op0_register());
            store_offset = Some(instruction.memory_displacement64());
        }
        if let (Some(root), Some(offset)) = (root_register, store_offset) {
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.memory_base() == root
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == offset
            {
                vtable_register = Some(instruction.op0_register());
            }
        }
        if let Some(vtable) = vtable_register {
            if instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.memory_base() == vtable
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == (CONFIG_SET_UINT64_SLOT * 8) as u64
            {
                setter_register = Some(instruction.op0_register());
            }
        }
        if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_register() == Register::ESI
            && instruction.op1_kind() == OpKind::Immediate32
            && instruction.immediate32() == 1
        {
            install_store = true;
        }
        let calls_loaded_setter = setter_register.is_some_and(|setter| {
            instruction.flow_control() == FlowControl::IndirectCall
                && instruction.op0_kind() == OpKind::Register
                && instruction.op0_register() == setter
        });
        let calls_direct_setter = vtable_register.is_some_and(|vtable| {
            instruction.flow_control() == FlowControl::IndirectCall
                && instruction.op0_kind() == OpKind::Memory
                && instruction.memory_base() == vtable
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() == (CONFIG_SET_UINT64_SLOT * 8) as u64
        });
        if calls_loaded_setter || calls_direct_setter {
            setter_called = store_register == Some(Register::RDI)
                && key_registers.contains(&Register::RDX)
                && install_store;
        }
    }

    if !setter_called {
        return Err(
            "x86_64 SetUint64 call does not use rdi/store, esi=1, and rdx/ClientID key"
                .to_owned(),
        );
    }
    let root_slot_va = root_slot_va.ok_or_else(|| "RIP-relative config root was not found".to_owned())?;
    if !image.in_module(root_slot_va) || image.in_text(root_slot_va) {
        return Err(format!(
            "RIP-relative root slot 0x{root_slot_va:x} is not module data"
        ));
    }
    Ok(ClientIdBehavior {
        root_slot_va,
        store_offset: store_offset.ok_or_else(|| "embedded CConfigStore offset was not found".to_owned())?,
        streaming_key_va: streaming_key_va
            .ok_or_else(|| "streaming/ClientID RIP reference was not found".to_owned())?,
        site_license_key_va: site_license_key_va
            .ok_or_else(|| "sitelicense/ClientID RIP reference was not found".to_owned())?,
        key_addressing: "RIP-relative",
    })
}

fn scan_steamui64_layouts(code: &[u8], vaddr: u64, resolved: &HashMap<&str, usize>) -> bool {
    let mut failed = false;
    failed |= scan_semantic_checks(
        code,
        vaddr,
        resolved,
        STEAMUI64_SEMANTIC_CHECKS,
        SemanticArch::X86_64,
    );

    if let Some(&add_offset) = resolved.get("google::protobuf::RepeatedField<uint32>::Add") {
        if is_x64_reflection_repeated_field_setter(code, add_offset) {
            println!(
                "  FAIL {:<58} va=0x{:x} required (resolved protobuf reflection helper, not 2-arg Add ABI)",
                "google::protobuf::RepeatedField<uint32>::Add ABI",
                vaddr + add_offset as u64
            );
            failed = true;
        }
    }

    if let Some(&fill_offset) = resolved.get("CSteamUIAppController::FillInAppOverview") {
        match discover_steam_app64_layout(code, fill_offset) {
            Some(layout) => println!(
                "  OK   {:<58} game_id=0x{:x} app_id=0x{:x} purchased_time=0x{:x}",
                "CSteamApp layout",
                layout.game_id_off,
                layout.app_id_off,
                layout.purchased_time_off
            ),
            None => {
                let evidence = fill_in_app_overview64_evidence(code, fill_offset);
                print_evidence_failure(
                    "CSteamApp layout",
                    vaddr + fill_offset as u64,
                    evidence.as_ref(),
                    "layout discovery failed",
                );
                failed = true;
            }
        }
    }

    if let Some(&build_offset) =
        resolved.get("CSteamUIAppController::BuildCompleteAppOverviewChange")
    {
        match discover_app_overview_change64_layout(code, build_offset) {
            Some(layout) => println!(
                "  OK   {:<58} app_overview=0x{:x} removed_appid=0x{:x}",
                "CAppOverviewChange layout", layout.app_overview_off, layout.removed_appid_off
            ),
            None => {
                let evidence = build_complete_app_overview_change64_evidence(code, build_offset);
                print_evidence_failure(
                    "CAppOverviewChange layout",
                    vaddr + build_offset as u64,
                    evidence.as_ref(),
                    "layout discovery failed",
                );
                failed = true;
            }
        }
    }

    failed
}

fn scan_steamui32_layouts(code: &[u8], vaddr: u64, resolved: &HashMap<&str, usize>) -> bool {
    let mut failed = false;
    failed |= scan_semantic_checks(
        code,
        vaddr,
        resolved,
        STEAMUI32_SEMANTIC_CHECKS,
        SemanticArch::X86,
    );

    if let Some(&fill_offset) = resolved.get("CSteamUIAppController::FillInAppOverview") {
        match discover_steam_app32_layout(code, fill_offset) {
            Some(layout) => println!(
                "  OK   {:<58} game_id=0x{:x} app_id=0x{:x} purchased_time=0x{:x}",
                "CSteamApp layout",
                layout.game_id_off,
                layout.app_id_off,
                layout.purchased_time_off
            ),
            None => {
                let evidence = fill_in_app_overview32_evidence(code, fill_offset);
                print_evidence_failure(
                    "CSteamApp layout",
                    vaddr + fill_offset as u64,
                    evidence.as_ref(),
                    "layout discovery failed",
                );
                failed = true;
            }
        }
    }

    if let Some(&build_offset) =
        resolved.get("CSteamUIAppController::BuildCompleteAppOverviewChange")
    {
        match discover_app_overview_change32_layout(code, build_offset) {
            Some(layout) => println!(
                "  OK   {:<58} app_overview=0x{:x} removed_appid=0x{:x}",
                "CAppOverviewChange layout", layout.app_overview_off, layout.removed_appid_off
            ),
            None => {
                let evidence = build_complete_app_overview_change32_evidence(code, build_offset);
                print_evidence_failure(
                    "CAppOverviewChange layout",
                    vaddr + build_offset as u64,
                    evidence.as_ref(),
                    "layout discovery failed",
                );
                failed = true;
            }
        }
    }

    failed
}

fn is_x64_reflection_repeated_field_setter(code: &[u8], offset: usize) -> bool {
    let Some(bytes) = code.get(offset..offset.saturating_add(0x40)) else {
        return false;
    };

    // The known bad x86_64 match is a protobuf reflection setter reached by
    // a tail-jump thunk. It consumes rdx/ecx/r8 in addition to rdi/rsi, so it
    // is not callable as RepeatedFieldAddFn(field, &value).
    bytes.starts_with(&[
        0x41, 0x55, // push r13
        0x48, 0x83, 0xc7, 0x08, // add rdi, 8
    ]) && bytes.windows(3).any(|w| w == [0x45, 0x89, 0xc5])
        && bytes.windows(3).any(|w| w == [0x41, 0x89, 0xcc])
        && bytes.windows(3).any(|w| w == [0x48, 0x89, 0xd5])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SteamAppLayout {
    game_id_off: usize,
    app_id_off: usize,
    purchased_time_off: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AppOverviewChangeLayout {
    app_overview_off: usize,
    removed_appid_off: usize,
}

fn discover_steam_app64_layout(
    code: &[u8],
    fill_in_app_overview_offset: usize,
) -> Option<SteamAppLayout> {
    let bytes = bounded_tail(code, fill_in_app_overview_offset, 0x900)?;

    let game_id_off = find_x64_rbp_dword_or_qword_load(bytes, 0x08)?;
    let app_id_off = find_x64_rbp_dword_or_qword_load(bytes, 0x10)?;
    let purchased_time_off = find_x64_rbp_dword_or_qword_load(bytes, 0x2c)?;

    Some(SteamAppLayout {
        game_id_off,
        app_id_off,
        purchased_time_off,
    })
}

fn discover_steam_app32_layout(
    code: &[u8],
    fill_in_app_overview_offset: usize,
) -> Option<SteamAppLayout> {
    let bytes = bounded_tail(code, fill_in_app_overview_offset, 0x900)?;

    let game_id_off = find_x86_steam_app_game_id_load(bytes)?;
    let app_id_off = find_x86_any_reg_disp8_load(bytes, 0x0c)?;
    let purchased_time_off = find_x86_any_reg_disp8_load(bytes, 0x28)?;

    Some(SteamAppLayout {
        game_id_off,
        app_id_off,
        purchased_time_off,
    })
}

fn discover_app_overview_change64_layout(
    code: &[u8],
    build_complete_offset: usize,
) -> Option<AppOverviewChangeLayout> {
    let bytes = bounded_tail(code, build_complete_offset, 0x200)?;
    if !bytes.windows(4).any(|w| w == [0x48, 0x8d, 0x7b, 0x18]) {
        return None;
    }
    if !bytes.windows(4).any(|w| w == [0xc6, 0x43, 0x40, 0x01])
        || !bytes.windows(4).any(|w| w == [0x83, 0x4b, 0x10, 0x01])
    {
        return None;
    }
    Some(AppOverviewChangeLayout {
        app_overview_off: 0x18,
        removed_appid_off: 0x28,
    })
}

fn discover_app_overview_change32_layout(
    code: &[u8],
    build_complete_offset: usize,
) -> Option<AppOverviewChangeLayout> {
    let bytes = bounded_tail(code, build_complete_offset, 0x120)?;
    if !bytes.windows(3).any(|w| w == [0x83, 0xc2, 0x10]) {
        return None;
    }
    if !bytes.windows(4).any(|w| w == [0xc6, 0x42, 0x2c, 0x01])
        || !bytes.windows(4).any(|w| w == [0x83, 0x4a, 0x08, 0x01])
    {
        return None;
    }
    Some(AppOverviewChangeLayout {
        app_overview_off: 0x10,
        removed_appid_off: 0x1c,
    })
}

fn bounded_tail(bytes: &[u8], offset: usize, max_len: usize) -> Option<&[u8]> {
    let tail = bytes.get(offset..)?;
    Some(&tail[..tail.len().min(max_len)])
}

fn has_seq(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && bytes.windows(needle.len()).any(|w| w == needle)
}

fn has_x86_cmp_eax_any_imm32(bytes: &[u8], values: &[u32]) -> bool {
    values
        .iter()
        .any(|&value| has_x86_cmp_eax_imm32(bytes, value))
}

fn has_asm32(
    bytes: &[u8],
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
) -> bool {
    has_asm(bytes, 32, build)
}

fn asm_bytes32(
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
) -> Option<Vec<u8>> {
    asm_bytes(32, build)
}

fn has_asm64(
    bytes: &[u8],
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
) -> bool {
    has_asm(bytes, 64, build)
}

fn asm_bytes64(
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
) -> Option<Vec<u8>> {
    asm_bytes(64, build)
}

fn has_asm(
    bytes: &[u8],
    bitness: u32,
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
) -> bool {
    let Some(needle) = asm_bytes(bitness, build) else {
        return false;
    };
    has_seq(bytes, &needle)
}

fn asm_bytes(
    bitness: u32,
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
) -> Option<Vec<u8>> {
    let Ok(mut asm) = iced_x86::code_asm::CodeAssembler::new(bitness) else {
        return None;
    };
    if build(&mut asm).is_err() {
        return None;
    }
    let Ok(needle) = asm.assemble(0) else {
        return None;
    };
    Some(needle)
}

fn has_x86_mov_from_esi_disp8(bytes: &[u8], disp: u8) -> bool {
    bytes.windows(3).any(|w| {
        w[0] == 0x8b && (0x40..=0x7f).contains(&w[1]) && (w[1] & 0x07) == 0x06 && w[2] == disp
    })
}

fn has_x86_mov_from_any_disp8(bytes: &[u8], disp: u8) -> bool {
    bytes
        .windows(3)
        .any(|w| w[0] == 0x8b && (0x40..=0x7f).contains(&w[1]) && w[2] == disp)
}

fn has_x86_mov_edi_from_esi_disp32(bytes: &[u8], accepted_disps: &[u32]) -> bool {
    bytes.windows(6).any(|w| {
        if w[0] != 0x8b || w[1] != 0xbe {
            return false;
        }
        let disp = u32::from_le_bytes([w[2], w[3], w[4], w[5]]);
        accepted_disps.is_empty() || accepted_disps.contains(&disp)
    })
}

fn has_x86_lea_eax_from_esi_disp32(bytes: &[u8], accepted_disps: &[u32]) -> bool {
    bytes.windows(6).any(|w| {
        if w[0] != 0x8d || w[1] != 0x86 {
            return false;
        }
        let disp = u32::from_le_bytes([w[2], w[3], w[4], w[5]]);
        accepted_disps.is_empty() || accepted_disps.contains(&disp)
    })
}

fn has_x86_license_vector_load32(bytes: &[u8]) -> bool {
    has_x86_mov_edi_from_esi_disp32(bytes, &[0x1B14, 0x1B18])
}

fn has_x86_license_vector_base32(bytes: &[u8]) -> bool {
    has_x86_lea_eax_from_esi_disp32(bytes, &[0x1AE4, 0x1AE8])
}

fn has_x86_shl_rm32_by_2(bytes: &[u8]) -> bool {
    bytes
        .windows(3)
        .any(|w| w[0] == 0xc1 && (0xe0..=0xe7).contains(&w[1]) && w[2] == 0x02)
}

fn has_x86_and_eax_imm8(bytes: &[u8], imm: u8) -> bool {
    has_seq(bytes, &[0x83, 0xe0, imm])
}

fn has_x86_or_al_imm8(bytes: &[u8], imm: u8) -> bool {
    has_seq(bytes, &[0x0c, imm])
}

fn has_x86_sub_eax_imm8(bytes: &[u8], imm: u8) -> bool {
    has_seq(bytes, &[0x83, 0xe8, imm])
}

fn has_x86_cmp_eax_imm32(bytes: &[u8], imm: u32) -> bool {
    let imm = imm.to_le_bytes();
    bytes.windows(5).any(|w| w[0] == 0x3d && w[1..5] == imm)
}

fn has_x86_fstp_esp_disp8(bytes: &[u8], disp: u8) -> bool {
    has_seq(bytes, &[0xd9, 0x5c, 0x24, disp])
}

fn find_x86_sub_eax_imm32_matching(
    bytes: &[u8],
    mut matches_imm: impl FnMut(u32) -> bool,
) -> Option<u32> {
    bytes.windows(5).find_map(|w| {
        if w[0] != 0x2d {
            return None;
        }
        let imm = u32::from_le_bytes([w[1], w[2], w[3], w[4]]);
        matches_imm(imm).then_some(imm)
    })
}

fn has_x86_test_ebp_disp8_imm8(bytes: &[u8], disp: u8, imm: u8) -> bool {
    has_seq(bytes, &[0xf6, 0x45, disp, imm])
}

fn has_x86_cmp_rm32_imm8(bytes: &[u8], disp: u32, imm: u8) -> bool {
    let disp = disp.to_le_bytes();
    bytes
        .windows(7)
        .any(|w| w[0] == 0x83 && matches!(w[1], 0xb8..=0xbf) && w[2..6] == disp && w[6] == imm)
}

fn has_x86_rm32_disp32_load(bytes: &[u8], disp: u32) -> bool {
    let disp = disp.to_le_bytes();
    bytes
        .windows(6)
        .any(|w| w[0] == 0x8b && matches!(w[1], 0x80..=0xbf) && w[2..6] == disp)
}

fn has_x86_ebp_store_i32(bytes: &[u8], value: i32) -> bool {
    let value = value.to_le_bytes();
    bytes.windows(7).any(|w| {
        w[0] == 0xc7
            && matches!(w[1], 0x40..=0x7f)
            && w[3] == value[0]
            && w[4] == value[1]
            && w[5] == value[2]
            && w[6] == value[3]
    }) || bytes.windows(10).any(|w| {
        w[0] == 0xc7
            && matches!(w[1], 0x80..=0xbf)
            && w[6] == value[0]
            && w[7] == value[1]
            && w[8] == value[2]
            && w[9] == value[3]
    })
}

fn has_x86_call_after(bytes: &[u8], marker: &[u8], max_distance: usize) -> bool {
    bytes.windows(marker.len()).enumerate().any(|(idx, w)| {
        w == marker
            && bytes[idx + marker.len()..bytes.len().min(idx + marker.len() + max_distance)]
                .contains(&0xe8)
    })
}

fn has_asm32_call_after(
    bytes: &[u8],
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
    max_distance: usize,
) -> bool {
    let Some(marker) = asm_bytes32(build) else {
        return false;
    };
    has_x86_call_after(bytes, &marker, max_distance)
}

fn has_asm64_call_after(
    bytes: &[u8],
    build: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
    max_distance: usize,
) -> bool {
    let Some(marker) = asm_bytes64(build) else {
        return false;
    };
    has_x86_call_after(bytes, &marker, max_distance)
}

fn has_x86_push_edx_call_after(bytes: &[u8], max_distance: usize) -> bool {
    has_x86_call_after(bytes, &[0x52], max_distance)
}

fn has_x64_rsp_store_cl(bytes: &[u8]) -> bool {
    bytes
        .windows(4)
        .any(|w| w[0] == 0x88 && w[1] == 0x4c && w[2] == 0x24)
}

fn has_x64_stack_spill_r32(bytes: &[u8], reg: u8) -> bool {
    let modrm = 0x44 | ((reg & 0x07) << 3);
    bytes
        .windows(4)
        .any(|w| w[0] == 0x89 && w[1] == modrm && w[2] == 0x24)
}

fn has_x64_movsd_rbp_disp32_from_xmm0(bytes: &[u8], disp: i32) -> bool {
    let disp = disp.to_le_bytes();
    bytes
        .windows(8)
        .any(|w| w[0] == 0xf2 && w[1] == 0x0f && w[2] == 0x11 && w[3] == 0x85 && w[4..8] == disp)
}

fn has_x64_push_rbp_negative_local_before_call(bytes: &[u8]) -> bool {
    bytes.windows(7).enumerate().any(|(idx, w)| {
        if w[0] != 0x48
            || w[1] != 0x8d
            || w[2] != 0x85
            || i32::from_le_bytes([w[3], w[4], w[5], w[6]]) >= 0
        {
            return false;
        }
        let after_lea = &bytes[idx + 7..bytes.len().min(idx + 0x50)];
        let Some(push_rax_at) = after_lea.iter().position(|&byte| byte == 0x50) else {
            return false;
        };
        after_lea[push_rax_at + 1..].contains(&0xe8)
    })
}

fn has_x64_rm32_disp32_load(bytes: &[u8], disp: u32) -> bool {
    let disp = disp.to_le_bytes();
    bytes
        .windows(6)
        .any(|w| w[0] == 0x8b && matches!(w[1], 0x80..=0xbf) && w[2..6] == disp)
        || bytes
            .windows(7)
            .any(|w| w[0] == 0x44 && w[1] == 0x8b && matches!(w[2], 0x80..=0xbf) && w[3..7] == disp)
}

fn has_x64_rip_lea(bytes: &[u8], modrm: u8) -> bool {
    bytes
        .windows(7)
        .any(|w| w[0] == 0x48 && w[1] == 0x8d && w[2] == modrm)
}

fn semantic_failure_evidence(
    arch: SemanticArch,
    name: &str,
    code: &[u8],
    offset: usize,
) -> Option<Evidence> {
    match (arch, name) {
        (SemanticArch::X86, "CUser::CheckAppOwnership") => {
            check_app_ownership32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUser::CheckAppOwnership") => {
            check_app_ownership64_evidence(code, offset)
        }
        (SemanticArch::X86, "CUser::GetSubscribedApps") => {
            get_subscribed_apps32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUser::GetSubscribedApps") => {
            get_subscribed_apps64_evidence(code, offset)
        }
        (SemanticArch::X86, "CSteamEngine::Init") => steam_engine_init32_evidence(code, offset),
        (SemanticArch::X86_64, "CSteamEngine::Init") => {
            steam_engine_init64_evidence(code, offset)
        }
        (SemanticArch::X86, "CSteamEngine::SetAPICallResult") => {
            set_api_call_result32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CSteamEngine::SetAPICallResult") => {
            set_api_call_result64_evidence(code, offset)
        }
        (SemanticArch::X86, "IClientRemoteStorage::RunIPCFrame")
        | (SemanticArch::X86, "IClientAppManager::RunIPCFrame")
        | (SemanticArch::X86, "IClientApps::RunIPCFrame") => ipc_run_frame32_evidence(code, offset),
        (SemanticArch::X86, "CUserStats::SetStat(int32)") => {
            set_stat_adapter32_evidence(code, offset, 0xe4)
        }
        (SemanticArch::X86, "CUserStats::SetStat(float)") => {
            set_stat_adapter32_evidence(code, offset, 0xe8)
        }
        (SemanticArch::X86, "CUserStats::SetAchievement") => {
            named_achievement_adapter32_evidence(code, offset, 0xf0)
        }
        (SemanticArch::X86, "CUserStats::ClearAchievement") => {
            named_achievement_adapter32_evidence(code, offset, 0xf4)
        }
        (SemanticArch::X86, "CUserStats::StoreStats") => {
            store_stats_adapter32_evidence(code, offset)
        }
        (SemanticArch::X86, "CUserStats::IndicateAchievementProgress") => {
            achievement_progress_adapter32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "IClientRemoteStorage::RunIPCFrame")
        | (SemanticArch::X86_64, "IClientAppManager::RunIPCFrame")
        | (SemanticArch::X86_64, "IClientApps::RunIPCFrame") => {
            ipc_run_frame64_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUserStats::SetStat(int32)") => {
            set_stat_int_adapter64_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUserStats::SetStat(float)") => {
            set_stat_float_adapter64_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUserStats::SetAchievement") => {
            set_achievement_adapter64_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUserStats::ClearAchievement") => {
            clear_achievement_adapter64_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUserStats::StoreStats") => {
            store_stats_adapter64_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUserStats::IndicateAchievementProgress") => {
            achievement_progress_adapter64_evidence(code, offset)
        }
        (SemanticArch::X86, "LoadDepotDecryptionKey") => load_depot_key32_evidence(code, offset),
        (SemanticArch::X86_64, "LoadDepotDecryptionKey") => load_depot_key64_evidence(code, offset),
        (SemanticArch::X86, "BuildDepotDependency") => {
            build_depot_dependency32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "BuildDepotDependency") => {
            build_depot_dependency64_evidence(code, offset)
        }
        (SemanticArch::X86, "CWebSocketConnection::BBuildAndAsyncSendFrame") => {
            websocket_send_frame32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CWebSocketConnection::BBuildAndAsyncSendFrame") => {
            websocket_send_frame64_evidence(code, offset)
        }
        (SemanticArch::X86, "CCMConnection::RecvPkt") => ccm_recv_pkt32_evidence(code, offset),
        (SemanticArch::X86_64, "CCMConnection::RecvPkt") => ccm_recv_pkt64_evidence(code, offset),
        (SemanticArch::X86, "CHTTPRequestJob::Start") => {
            http_request_job_start32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CHTTPRequestJob::Start") => {
            http_request_job_start64_evidence(code, offset)
        }
        (SemanticArch::X86, "CUser::MarkLicenseAsChanged") => {
            mark_license_changed32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUser::MarkLicenseAsChanged") => {
            mark_license_changed64_evidence(code, offset)
        }
        (SemanticArch::X86, "CUser::ProcessPendingLicenseUpdates") => {
            process_pending_license_updates32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUser::ProcessPendingLicenseUpdates") => {
            process_pending_license_updates64_evidence(code, offset)
        }
        (SemanticArch::X86, "CUtlMemory::Grow") => cutl_memory_grow32_evidence(code, offset),
        (SemanticArch::X86_64, "CUtlMemory::Grow") => cutl_memory_grow64_evidence(code, offset),
        (SemanticArch::X86, "CConfigStore::WriteVdfFile") => {
            write_vdf_file32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CConfigStore::WriteVdfFile") => {
            write_vdf_file64_evidence(code, offset)
        }
        (SemanticArch::X86, "CUser::SpawnProcess") => spawn_process32_evidence(code, offset),
        (SemanticArch::X86_64, "CUser::SpawnProcess") => spawn_process64_evidence(code, offset),
        (SemanticArch::X86, "CUser::BuildSpawnEnvBlock") => {
            build_spawn_env_block32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUser::BuildSpawnEnvBlock") => {
            build_spawn_env_block64_evidence(code, offset)
        }
        (SemanticArch::X86, "SetEnvString") => set_env_string32_evidence(code, offset),
        (SemanticArch::X86_64, "SetEnvString") => set_env_string64_evidence(code, offset),
        (SemanticArch::X86, "CSteamUIAppController::RunFrame") => {
            steamui_run_frame32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CSteamUIAppController::RunFrame") => {
            steamui_run_frame64_evidence(code, offset)
        }
        (SemanticArch::X86, "CSteamUIAppController::FillInAppOverview") => {
            fill_in_app_overview32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CSteamUIAppController::FillInAppOverview") => {
            fill_in_app_overview64_evidence(code, offset)
        }
        (SemanticArch::X86, "CSteamUIAppController::BuildCompleteAppOverviewChange") => {
            build_complete_app_overview_change32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CSteamUIAppController::BuildCompleteAppOverviewChange") => {
            build_complete_app_overview_change64_evidence(code, offset)
        }
        (SemanticArch::X86, "CSteamUIAppController::GetAppByID") => {
            get_app_by_id32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CSteamUIAppController::GetAppByID") => {
            get_app_by_id64_evidence(code, offset)
        }
        (SemanticArch::X86, "CUpdateManager::MarkAppChange") => {
            mark_app_change32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "CUpdateManager::MarkAppChange") => {
            mark_app_change64_evidence(code, offset)
        }
        (SemanticArch::X86, "google::protobuf::RepeatedField<uint32>::Add") => {
            repeated_field_add32_evidence(code, offset)
        }
        (SemanticArch::X86_64, "google::protobuf::RepeatedField<uint32>::Add") => {
            repeated_field_add64_evidence(code, offset)
        }
        _ => None,
    }
}

fn validate_check_app_ownership32(code: &[u8], offset: usize) -> Option<&'static str> {
    check_app_ownership32_evidence(code, offset)?
        .is_complete()
        .then_some("ownership result + license state")
}

fn check_app_ownership32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x360)?;
    let has_result_frame = has_asm32(bytes, |a| a.sub(esp, 0xACu32))
        && (has_asm32(bytes, |a| a.mov(ecx, 8)) || has_asm32(bytes, |a| a.mov(ecx, 0x0D)))
        && (has_asm32(bytes, |a| a.mov(dword_ptr(eax), -1))
            || has_asm32(bytes, |a| a.mov(dword_ptr(esi), -1)));
    let has_license_state = (has_x86_rm32_disp32_load(bytes, 0x1bd4)
        && has_x86_rm32_disp32_load(bytes, 0x1bf0))
        || (has_x86_rm32_disp32_load(bytes, 0x1bd0) && has_x86_rm32_disp32_load(bytes, 0x1bec));
    let has_success_flags = (has_asm32(bytes, |a| a.mov(byte_ptr(eax + 0x28), 1))
        || has_asm32(bytes, |a| a.mov(byte_ptr(esi + 0x28), 1)))
        && (has_asm32(bytes, |a| a.mov(byte_ptr(eax + 0x30), 1))
            || has_asm32(bytes, |a| a.mov(byte_ptr(esi + 0x30), 1)))
        && (has_asm32(bytes, |a| a.mov(word_ptr(eax + 0x33), bx))
            || has_asm32(bytes, |a| a.mov(word_ptr(esi + 0x33), di)));
    let has_owned_app_iteration = (has_asm32(bytes, |a| a.mov(ecx, dword_ptr(edi + 0x0C)))
        || has_asm32(bytes, |a| a.mov(eax, dword_ptr(edi + 0x0C)))
        || has_asm32(bytes, |a| a.mov(eax, dword_ptr(eax + 0x0C))))
        && (has_x86_rm32_disp32_load(bytes, 0x1bc8) || has_x86_rm32_disp32_load(bytes, 0x1bc4))
        && (has_asm32(bytes, |a| a.lea(edx, dword_ptr(eax + eax * 8)))
            || has_asm32(bytes, |a| a.lea(ecx, dword_ptr(edx + edx * 8))));

    let mut evidence = Evidence::default();
    evidence.require("ownership result frame", has_result_frame);
    evidence.require("license state offsets", has_license_state);
    evidence.require("success result writes", has_success_flags);
    evidence.require("owned app vector iteration", has_owned_app_iteration);
    Some(evidence)
}

fn validate_check_app_ownership64(code: &[u8], offset: usize) -> Option<&'static str> {
    check_app_ownership64_evidence(code, offset)?
        .is_complete()
        .then_some("ownership result + license state")
}

fn check_app_ownership64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x360)?;
    let old_result_frame = has_asm64(bytes, |a| a.sub(rsp, 0xB8))
        && has_asm64(bytes, |a| a.mov(ecx, 6))
        && has_asm64(bytes, |a| a.mov(dword_ptr(rsp + 0x70), -1));
    let current_result_frame = has_asm64(bytes, |a| a.sub(rsp, 0xB8))
        && has_asm64(bytes, |a| a.mov(eax, -1))
        && has_asm64(bytes, |a| a.mov(qword_ptr(rbx), rax));
    let has_license_state =
        has_x64_rm32_disp32_load(bytes, 0x2498) && has_x64_rm32_disp32_load(bytes, 0x24bc);
    let old_success_flags = has_asm64(bytes, |a| a.mov(byte_ptr(r14 + 0x28), 1))
        && has_asm64(bytes, |a| a.mov(byte_ptr(r14 + 0x30), 1))
        && has_asm64(bytes, |a| a.mov(word_ptr(r14 + 0x33), r8w));
    let current_success_flags = has_asm64(bytes, |a| a.mov(byte_ptr(rbx + 0x28), 1))
        && has_asm64(bytes, |a| a.mov(byte_ptr(rbx + 0x30), 1))
        && has_asm64(bytes, |a| a.mov(word_ptr(rbx + 0x33), r8w));
    let old_owned_app_iteration = has_asm64(bytes, |a| a.mov(eax, dword_ptr(rax + 0x10)))
        && has_asm64(bytes, |a| a.movsxd(rdx, dword_ptr(rdx + r13 * 4)));
    let current_owned_app_iteration = has_asm64(bytes, |a| a.mov(edx, dword_ptr(rax + 0x10)))
        && has_asm64(bytes, |a| a.movsxd(rax, dword_ptr(rax + r12 * 4)));

    let mut evidence = Evidence::default();
    evidence.require("ownership result frame", old_result_frame || current_result_frame);
    evidence.require("license state offsets", has_license_state);
    evidence.require("success result writes", old_success_flags || current_success_flags);
    evidence.require(
        "owned app vector iteration",
        old_owned_app_iteration || current_owned_app_iteration,
    );
    Some(evidence)
}

fn validate_get_subscribed_apps32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        get_subscribed_apps32_evidence(code, offset),
        "args=appid-list flags",
    )
}

fn get_subscribed_apps32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x100)?;
    Some(Evidence::required([
        (
            "subscription flag argument",
            has_asm32(bytes, |a| a.movzx(eax, byte_ptr(ebp + 0x14))),
        ),
        (
            "appid list source",
            has_asm32(bytes, |a| {
                a.push(0)?;
                a.push(0)
            }) || has_asm32(bytes, |a| a.mov(edx, dword_ptr(ecx + 0x1BD0))),
        ),
    ]))
}

fn validate_get_subscribed_apps64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        get_subscribed_apps64_evidence(code, offset),
        "args=appid-list flags",
    )
}

fn get_subscribed_apps64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x260)?;
    let old_license_entry = has_asm64(bytes, |a| a.lea(rbx, qword_ptr(r15 + r15 * 4)))
        && has_asm64(bytes, |a| a.shl(rbx, 4))
        && has_asm64(bytes, |a| a.add(rbx, qword_ptr(r12 + 0x2488)))
        && has_asm64(bytes, |a| a.mov(r13d, dword_ptr(rbx)))
        && has_asm64(bytes, |a| a.cmp(r13d, -1));
    let current_license_entry = has_asm64(bytes, |a| a.lea(rbx, qword_ptr(r13 + r13 * 4)))
        && has_asm64(bytes, |a| a.shl(rbx, 4))
        && has_asm64(bytes, |a| a.add(rbx, qword_ptr(rdi + 0x2488)))
        && has_asm64(bytes, |a| a.mov(r12d, dword_ptr(rbx)))
        && has_asm64(bytes, |a| a.cmp(r12d, -1));
    Some(Evidence::required([
        (
            "include hidden subscriptions flag",
            has_x64_rsp_store_cl(bytes),
        ),
        (
            "license vector count",
            has_asm64(bytes, |a| a.mov(eax, dword_ptr(rdi + 0x2498)))
                || has_asm64(bytes, |a| a.mov(eax, dword_ptr(rbx + 0x2498))),
        ),
        ("known license entry layout", old_license_entry || current_license_entry),
        (
            "package lookup state",
            has_asm64(bytes, |a| a.add(rdi, 0x1018))
                && has_asm64(bytes, |a| a.cmp(dword_ptr(rax + 0x18), 3)),
        ),
    ]))
}

fn validate_steam_engine_init32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        steam_engine_init32_evidence(code, offset),
        "CSteamEngine object initialization",
    )
}

fn steam_engine_init32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x300)?;
    Some(Evidence::required([
        ("primary vtable write", has_seq(bytes, &[0x89, 0x06])),
        (
            "secondary vtable write at +0x9f0",
            has_seq(bytes, &[0x89, 0x86, 0xf0, 0x09, 0x00, 0x00]),
        ),
        (
            "engine member initialization at +0xa20",
            has_seq(bytes, &[0x8d, 0x86, 0x20, 0x0a, 0x00, 0x00]),
        ),
    ]))
}

fn validate_steam_engine_init64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        steam_engine_init64_evidence(code, offset),
        "CSteamEngine object initialization",
    )
}

fn steam_engine_init64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x300)?;
    Some(Evidence::required([
        ("primary vtable write", has_asm64(bytes, |a| a.mov(qword_ptr(rbx), rax))),
        (
            "secondary vtable write at +0xcf0",
            has_asm64(bytes, |a| a.mov(qword_ptr(rbx + 0xcf0), rax)),
        ),
        (
            "engine member initialization at +0xd28",
            has_asm64(bytes, |a| a.lea(rax, qword_ptr(rbx + 0xd28))),
        ),
    ]))
}

fn validate_set_api_call_result32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        set_api_call_result32_evidence(code, offset),
        "api-call map + callback posting",
    )
}

fn set_api_call_result32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x520)?;
    Some(Evidence::required([
        (
            "api-call map root/index offset",
            has_x86_rm32_disp32_load(bytes, 0x14ac),
        ),
        (
            "api-call map storage offset",
            has_x86_rm32_disp32_load(bytes, 0x14c0),
        ),
        (
            "api-call node stride 0x30",
            has_asm32(bytes, |a| a.push(0x30)),
        ),
        (
            "callback object virtual dispatch",
            has_asm32(bytes, |a| a.call(dword_ptr(eax + 0x10)))
                || has_asm32(bytes, |a| a.call(dword_ptr(ecx + 0x10)))
                || has_asm32(bytes, |a| a.call(dword_ptr(edx + 0x10))),
        ),
        (
            "SteamAPICallCompleted callback id",
            has_asm32(bytes, |a| a.push(0x2bf)),
        ),
        (
            "callback payload size",
            has_asm32(bytes, |a| a.push(0x10)),
        ),
    ]))
}

fn validate_set_api_call_result64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        set_api_call_result64_evidence(code, offset),
        "api-call map + callback posting",
    )
}

fn set_api_call_result64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x520)?;
    let has_map_base = has_asm64(bytes, |a| a.add(rdi, 0x19a8))
        || has_asm64(bytes, |a| a.lea(rdi, qword_ptr(r13 + 0x19a8)));
    let has_storage = has_asm64(bytes, |a| a.mov(rcx, qword_ptr(rdi + 0x19d8)))
        || has_asm64(bytes, |a| a.mov(r9, qword_ptr(r13 + 0x19d8)))
        || has_asm64(bytes, |a| a.add(r15, qword_ptr(r14 + 0x19d8)));
    let has_node_stride = has_asm64(bytes, |a| a.imul_3(rbx, rbx, 0x38))
        || has_asm64(bytes, |a| a.imul_3(r15, r15, 0x38));
    Some(Evidence::required([
        ("api-call map base offset", has_map_base),
        ("api-call map storage offset", has_storage),
        ("api-call node stride 0x38", has_node_stride),
        (
            "callback object virtual dispatch",
            has_asm64(bytes, |a| a.call(qword_ptr(rax + 0x20))),
        ),
        (
            "SteamAPICallCompleted callback id",
            has_asm64(bytes, |a| a.mov(edx, 0x2bf)),
        ),
        (
            "callback payload size",
            has_asm64(bytes, |a| a.mov(r8d, 0x10)),
        ),
    ]))
}

fn validate_ipc_run_frame32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        ipc_run_frame32_evidence(code, offset),
        "ipc-wrapper mode=4 dispatch",
    )
}

fn ipc_run_frame32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x900)?;
    Some(Evidence::required([
        ("mode=4 ipc argument", has_asm32(bytes, |a| a.push(4))),
        (
            "known ipc dispatch id",
            has_x86_cmp_eax_any_imm32(
                bytes,
                &[
                    0x872F_E86C,
                    0x872F_E86D,
                    0x872F_E86E,
                    0x7A0A_85B0,
                    0x7A0A_85B2,
                    0x7A0A_85B7,
                    0xA688_9C36,
                    0xA688_9C37,
                    0xA688_9C39,
                ],
            ),
        ),
    ]))
}

fn validate_ipc_run_frame64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        ipc_run_frame64_evidence(code, offset),
        "ipc-wrapper mode=4 dispatch",
    )
}

fn ipc_run_frame64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x500)?;
    Some(Evidence::required([
        ("mode=4 ipc argument", has_asm64(bytes, |a| a.mov(edx, 4))),
        (
            "known ipc dispatch id",
            has_x86_cmp_eax_any_imm32(
                bytes,
                &[
                    0x872F_E86C,
                    0x872F_E86D,
                    0x7A0A_85B0,
                    0x7A0A_85B7,
                    0xA688_9C36,
                    0xA688_9C37,
                ],
            ),
        ),
    ]))
}

fn set_stat_adapter32_evidence(
    code: &[u8],
    offset: usize,
    implementation_slot: u8,
) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x120)?;
    let old_shape = has_seq(bytes, &[0x8b, 0x6c, 0x24, 0x4c])
        && has_seq(bytes, &[0x8b, 0x44, 0x24, 0x50, 0xf3, 0x0f, 0x7e, 0x08])
        && has_seq(bytes, &[0xff, 0xd0, 0x83, 0xc4, 0x4c]);
    let current_shape = has_seq(bytes, &[0x83, 0xec, 0x48])
        && has_seq(bytes, &[0x8b, 0x74, 0x24, 0x5c, 0x8b, 0x06])
        && has_seq(bytes, &[0x8b, 0x44, 0x24, 0x60, 0xf3, 0x0f, 0x7e, 0x00])
        && has_seq(bytes, &[0xff, 0xd7, 0x83, 0xc4, 0x20]);
    Some(Evidence::required([
        ("known cdecl adapter layout", old_shape || current_shape),
        (
            "typed SetStat implementation slot",
            has_seq(bytes, &[0x8b, 0x80, implementation_slot, 0x00, 0x00, 0x00])
                || has_seq(bytes, &[0x8b, 0xb8, implementation_slot, 0x00, 0x00, 0x00]),
        ),
    ]))
}

fn named_achievement_adapter32_evidence(
    code: &[u8],
    offset: usize,
    implementation_slot: u8,
) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x120)?;
    let old_shape = has_seq(bytes, &[0x8b, 0x6c, 0x24, 0x4c])
        && has_seq(bytes, &[0x8b, 0x44, 0x24, 0x50, 0xf3, 0x0f, 0x7e, 0x08])
        && has_seq(bytes, &[0xff, 0x74, 0x24, 0x54])
        && has_seq(bytes, &[0xff, 0xd0, 0x83, 0xc4, 0x4c]);
    let current_shape = has_seq(bytes, &[0x83, 0xec, 0x48])
        && has_seq(bytes, &[0x8b, 0x74, 0x24, 0x5c, 0x8b, 0x06])
        && has_seq(bytes, &[0x8b, 0x44, 0x24, 0x60, 0xf3, 0x0f, 0x7e, 0x00])
        && has_seq(bytes, &[0xff, 0xd7, 0x83, 0xc4, 0x20]);
    let current_clear_shape = implementation_slot == 0xf4
        && has_seq(bytes, &[0x83, 0xec, 0x5c])
        && has_seq(bytes, &[0x8b, 0x74, 0x24, 0x70])
        && has_seq(bytes, &[0x8b, 0x06, 0x8b, 0x80, 0xf4, 0x00, 0x00, 0x00])
        && has_seq(bytes, &[0x8b, 0x44, 0x24, 0x7c, 0xf3, 0x0f, 0x7e, 0x00]);
    Some(Evidence::required([
        (
            "known named adapter layout",
            old_shape || current_shape || current_clear_shape,
        ),
        (
            "named achievement implementation slot",
            has_seq(bytes, &[0x8b, 0x80, implementation_slot, 0x00, 0x00, 0x00])
                || has_seq(bytes, &[0x8b, 0xb8, implementation_slot, 0x00, 0x00, 0x00]),
        ),
    ]))
}

fn store_stats_adapter32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    Some(Evidence::required([
        (
            "cdecl CGameID argument",
            has_seq(bytes, &[0x8b, 0x45, 0x0c, 0x8b, 0x30, 0x8b, 0x58, 0x04])
                || has_seq(bytes, &[0x8b, 0x45, 0x0c, 0x8b, 0x38, 0x8b, 0x40, 0x04]),
        ),
        (
            "CGameID validation",
            has_seq(bytes, &[0xc1, 0xe8, 0x18])
                && (has_seq(bytes, &[0xf7, 0xc6, 0xff, 0xff, 0xff, 0x00])
                    || has_seq(bytes, &[0xf7, 0xc7, 0xff, 0xff, 0xff, 0x00])),
        ),
        (
            "StoreStats result preservation",
            has_seq(bytes, &[0x89, 0xc7, 0x74]),
        ),
    ]))
}

fn set_stat_int_adapter64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x80)?;
    let old_shape = has_asm64(bytes, |a| a.mov(rbp, rdx))
        && has_asm64(bytes, |a| a.mov(r12d, ecx))
        && has_asm64(bytes, |a| a.mov(qword_ptr(rsp), rax))
        && has_asm64(bytes, |a| a.mov(rdx, rsp));
    let current_shape = has_asm64(bytes, |a| a.mov(r12, rdx))
        && has_asm64(bytes, |a| a.mov(ebx, ecx))
        && has_asm64(bytes, |a| a.lea(rdx, qword_ptr(rsp + 0x08)));
    Some(Evidence::required([
        (
            "known integer adapter layout",
            old_shape || current_shape,
        ),
        (
            "int32 implementation slot",
            has_seq(bytes, &[0x4c, 0x8b, 0xa8, 0xc8, 0x01, 0x00, 0x00]),
        ),
        (
            "CGameID forwarding",
            has_asm64(bytes, |a| a.mov(rax, qword_ptr(rsi))),
        ),
    ]))
}

fn set_stat_float_adapter64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x80)?;
    let old_shape = has_asm64(bytes, |a| a.mov(rbp, rdx))
        && has_asm64(bytes, |a| a.mov(r12, qword_ptr(rax + 0x1D0)))
        && has_asm64(bytes, |a| a.lea(rdx, qword_ptr(rsp + 0x10)));
    let current_shape = has_asm64(bytes, |a| a.mov(r12, rdx))
        && has_asm64(bytes, |a| a.mov(rbx, qword_ptr(rax + 0x1D0)))
        && has_asm64(bytes, |a| a.lea(rdx, qword_ptr(rsp + 0x18)));
    Some(Evidence::required([
        (
            "float argument preservation",
            has_seq(bytes, &[0xf3, 0x0f, 0x11, 0x44, 0x24, 0x0c])
                && has_seq(bytes, &[0xf3, 0x0f, 0x10, 0x44, 0x24, 0x0c]),
        ),
        (
            "known float adapter layout",
            old_shape || current_shape,
        ),
        (
            "CGameID forwarding",
            has_asm64(bytes, |a| a.mov(rax, qword_ptr(rsi))),
        ),
    ]))
}

fn set_achievement_adapter64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x80)?;
    let old_shape = has_asm64(bytes, |a| a.mov(rbp, rdx))
        && has_asm64(bytes, |a| a.mov(r12, qword_ptr(rax + 0x1E0)))
        && has_asm64(bytes, |a| a.mov(qword_ptr(rsp), rax))
        && has_asm64(bytes, |a| a.mov(rdx, rsp));
    let current_shape = has_asm64(bytes, |a| a.mov(r12, rdx))
        && has_asm64(bytes, |a| a.mov(rbx, qword_ptr(rax + 0x1E0)))
        && has_asm64(bytes, |a| a.lea(rdx, qword_ptr(rsp + 0x08)));
    Some(Evidence::required([
        (
            "known SetAchievement adapter layout",
            old_shape || current_shape,
        ),
        (
            "CGameID forwarding",
            has_asm64(bytes, |a| a.mov(rax, qword_ptr(rsi))),
        ),
    ]))
}

fn clear_achievement_adapter64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    let old_shape = has_asm64(bytes, |a| a.mov(r12, rdx))
        && has_asm64(bytes, |a| a.mov(r13, qword_ptr(rax + 0x1E8)))
        && has_asm64(bytes, |a| a.movzx(eax, byte_ptr(rsp + 0x0B)));
    let current_shape = has_asm64(bytes, |a| a.mov(r13, rdx))
        && has_asm64(bytes, |a| a.mov(rbx, qword_ptr(rax + 0x1E8)))
        && has_asm64(bytes, |a| a.movzx(eax, byte_ptr(rsp + 0x13)));
    Some(Evidence::required([
        (
            "known ClearAchievement adapter layout",
            old_shape || current_shape,
        ),
        (
            "CGameID validation",
            has_asm64(bytes, |a| a.and(eax, 0x00FF_FFFF)),
        ),
    ]))
}

fn store_stats_adapter64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;
    let old_shape = has_asm64(bytes, |a| a.mov(r12, qword_ptr(rsi)))
        && has_asm64(bytes, |a| a.test(r12d, 0x00FF_FFFF))
        && has_asm64(bytes, |a| a.mov(ebp, eax))
        && has_asm64(bytes, |a| a.mov(eax, ebp));
    let current_shape = has_asm64(bytes, |a| a.mov(rbp, qword_ptr(rsi)))
        && has_asm64(bytes, |a| a.test(ebp, 0x00FF_FFFF))
        && has_asm64(bytes, |a| a.mov(r12d, eax))
        && has_asm64(bytes, |a| a.mov(eax, r12d));
    Some(Evidence::required([
        ("known StoreStats adapter layout", old_shape || current_shape),
        (
            "CGameID account type validation",
            has_asm64(bytes, |a| a.shr(rax, 0x18))
                && has_asm64(bytes, |a| a.cmp(al, 1))
                && has_asm64(bytes, |a| a.cmp(al, 2)),
        ),
    ]))
}

fn achievement_progress_adapter32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    let old_shape = has_asm32(bytes, |a| a.mov(eax, dword_ptr(esp + 0x40)))
        && has_asm32(bytes, |a| a.mov(esi, dword_ptr(esp + 0x44)))
        && has_asm32(bytes, |a| a.mov(ecx, dword_ptr(esp + 0x48)))
        && has_asm32(bytes, |a| a.mov(edi, dword_ptr(esp + 0x4C)))
        && has_asm32(bytes, |a| a.mov(ebp, dword_ptr(esp + 0x50)));
    let current_shape = has_seq(
        bytes,
        &[
            0x81, 0xec, 0x0c, 0x01, 0x00, 0x00, 0x8b, 0x8c, 0x24, 0x24, 0x01, 0x00,
            0x00,
        ],
    ) && has_seq(bytes, &[0x39, 0xbc, 0x24, 0x2c, 0x01, 0x00, 0x00]);
    Some(Evidence::required([
        ("known cdecl progress layout", old_shape || current_shape),
        (
            "CGameID validation",
            (has_asm32(bytes, |a| a.movzx(eax, byte_ptr(esi + 3)))
                && has_asm32(bytes, |a| a.and(eax, 0x00FF_FFFF)))
                || (has_asm32(bytes, |a| a.movzx(eax, byte_ptr(ecx + 3)))
                    && has_asm32(bytes, |a| a.cmp(al, 1))
                    && has_asm32(bytes, |a| a.cmp(al, 2))),
        ),
        (
            "progress argument repack",
            (has_asm32(bytes, |a| a.mov(dword_ptr(esp + 0x40), edi))
                && has_asm32(bytes, |a| a.mov(dword_ptr(esp + 0x44), ebp)))
                || current_shape,
        ),
        (
            "register-ABI tail adapter",
            (has_asm32(bytes, |a| a.mov(edx, esi))
                && has_seq(bytes, &[0x83, 0xC4, 0x2C, 0x5B, 0x5E, 0x5F, 0x5D, 0xE9]))
                || current_shape,
        ),
    ]))
}

fn achievement_progress_adapter64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x120)?;
    let old_shape = has_asm64(bytes, |a| a.mov(r15, rdx))
        && has_asm64(bytes, |a| a.mov(r14d, ecx))
        && has_asm64(bytes, |a| a.mov(r12, rsi))
        && has_asm64(bytes, |a| a.mov(ebx, r8d))
        && has_asm64(bytes, |a| a.movd(xmm2, ebx))
        && has_asm64(bytes, |a| a.movd(xmm1, r14d))
        && has_asm64(bytes, |a| a.punpckldq(xmm1, xmm2));
    let current_shape = has_asm64(bytes, |a| a.mov(r13, rdi))
        && has_asm64(bytes, |a| a.mov(r12d, ecx))
        && has_asm64(bytes, |a| a.mov(qword_ptr(rsp + 0x10), rdx))
        && has_asm64(bytes, |a| a.mov(dword_ptr(rsp + 0x1C), r8d))
        && has_asm64(bytes, |a| a.and(eax, 0x00FF_FFFF))
        && has_asm64(bytes, |a| a.mov(qword_ptr(rsi), rax))
        && has_seq(bytes, &[0x48, 0x83, 0xC4, 0x38, 0x44, 0x89, 0xE1, 0x4C, 0x89, 0xEF])
        && has_seq(bytes, &[0x41, 0x5C, 0x41, 0x5D, 0xE9]);
    Some(Evidence::required([
        (
            "known achievement progress adapter layout",
            old_shape || current_shape,
        ),
        (
            "CGameID account type validation",
            has_asm64(bytes, |a| a.movzx(eax, byte_ptr(rsi + 3)))
                && has_asm64(bytes, |a| a.cmp(al, 1))
                && has_asm64(bytes, |a| a.cmp(al, 2)),
        ),
    ]))
}

fn validate_load_depot_key32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        load_depot_key32_evidence(code, offset),
        "args=depot/key output",
    )
}

fn load_depot_key32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x120)?;
    Some(Evidence::required([
        (
            "depot id argument",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(esp + 0x44))),
        ),
        (
            "output buffer argument",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(esp + 0x48))),
        ),
        (
            "key loader call",
            has_asm32_call_after(
                bytes,
                |a| {
                    a.push(esi)?;
                    a.push(ebx)
                },
                0x08,
            ) || has_asm32_call_after(bytes, |a| a.push(dword_ptr(ebp + 0x0C)), 0x20),
        ),
    ]))
}

fn validate_load_depot_key64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(load_depot_key64_evidence(code, offset), "key-size=128")
}

fn load_depot_key64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x100)?;
    Some(Evidence::required([
        ("key size 128", has_asm64(bytes, |a| a.mov(esi, 0x80))),
        ("key buffer argument", has_asm64(bytes, |a| a.mov(rdi, rdx))),
    ]))
}

fn validate_build_depot_dependency32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        build_depot_dependency32_evidence(code, offset),
        "args=depot dependency",
    )
}

fn build_depot_dependency32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x220)?;
    let old_large_arg_form = has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x08)))
        && has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x10)))
        && has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x14)))
        && has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x24)))
        && has_asm32(bytes, |a| a.sub(esp, 0x22Cu32));
    let steamrt_arg_form = has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x08)))
        && has_asm32(bytes, |a| a.mov(ebx, dword_ptr(ebp + 0x10)))
        && has_asm32(bytes, |a| a.mov(esi, dword_ptr(ebp + 0x0C)))
        && has_asm32(bytes, |a| a.sub(esp, 0x6Cu32));
    Some(Evidence::required([
        (
            "known depot dependency arg form",
            old_large_arg_form || steamrt_arg_form,
        ),
        (
            "ownership result init",
            has_asm32(bytes, |a| a.mov(ecx, 0x0D)) && has_x86_ebp_store_i32(bytes, -1),
        ),
        (
            "CheckAppOwnership arguments",
            has_asm32_call_after(bytes, |a| a.push(dword_ptr(eax + 0x80)), 0x20),
        ),
        (
            "dependency state/result path",
            has_asm32(bytes, |a| a.add(edi, 0xB88u32))
                || has_asm32(bytes, |a| a.mov(dword_ptr(ebx + 0x14), eax)),
        ),
    ]))
}

fn validate_build_depot_dependency64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        build_depot_dependency64_evidence(code, offset),
        "args=depot dependency",
    )
}

fn build_depot_dependency64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    let old_shape = has_asm64(bytes, |a| a.mov(rax, qword_ptr(rsp + 0x2C8)))
        && has_asm64(bytes, |a| a.mov(dword_ptr(rsp + 0x130), -1))
        && has_asm64(bytes, |a| a.mov(rdi, qword_ptr(r14 + 0xF8)))
        && has_asm64(bytes, |a| a.add(rbp, 0xF20));
    let current_shape = has_asm64(bytes, |a| a.mov(rax, qword_ptr(rsp + 0x2E0)))
        && has_asm64(bytes, |a| a.mov(dword_ptr(rsp + 0x110), -1))
        && has_asm64(bytes, |a| a.mov(rdi, qword_ptr(r15 + 0xF8)))
        && (has_asm64(bytes, |a| a.add(rbp, 0xF20))
            || has_asm64(bytes, |a| a.add(r12, 0xF20)));
    Some(Evidence::required([
        (
            "known depot dependency layout",
            old_shape || current_shape,
        ),
        (
            "self-named profiling scope",
            has_asm64(bytes, |a| a.mov(esi, 4)) && has_x64_rip_lea(bytes, 0x3d),
        ),
        ("ownership result init", has_asm64(bytes, |a| a.mov(ecx, 6)) || has_asm64(bytes, |a| a.mov(ecx, 7))),
    ]))
}

fn validate_websocket_send_frame32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        websocket_send_frame32_evidence(code, offset),
        "websocket frame builder",
    )
}

fn websocket_send_frame32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x190)?;
    Some(Evidence::required([
        (
            "websocket open-state check",
            has_asm32(bytes, |a| a.cmp(dword_ptr(edx + 0x10), 2)),
        ),
        (
            "websocket frame header buffer",
            has_asm32(bytes, |a| a.sub(esp, 0xACu32)),
        ),
        (
            "header builder bounds",
            has_asm32(bytes, |a| a.push(0x40)) && has_asm32(bytes, |a| a.push(0x0E)),
        ),
        (
            "websocket opcode encoding",
            has_x86_and_eax_imm8(bytes, 0x0F) && has_x86_or_al_imm8(bytes, 0x80),
        ),
        (
            "payload length tiers",
            has_asm32(bytes, |a| a.cmp(dword_ptr(ebp + 0x14), 0x7D))
                && has_asm32(bytes, |a| a.cmp(dword_ptr(ebp + 0x14), 0xFFFF)),
        ),
        (
            "payload argument",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x10)))
                || has_asm32(bytes, |a| a.mov(dword_ptr(ebp - 0xA0), eax)),
        ),
    ]))
}

fn validate_websocket_send_frame64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        websocket_send_frame64_evidence(code, offset),
        "websocket frame builder",
    )
}

fn websocket_send_frame64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x1c0)?;
    let old_shape = has_asm64(bytes, |a| a.mov(r13d, esi))
        && has_asm64(bytes, |a| a.mov(rbx, rdx))
        && has_asm64(bytes, |a| a.cmp(ebp, 0xFFFF))
        && has_asm64(bytes, |a| a.xor(sil, byte_ptr(rbx + r14)))
        && has_asm64(bytes, |a| a.add(r14, 1));
    let current_shape = has_asm64(bytes, |a| a.mov(r14d, esi))
        && has_asm64(bytes, |a| a.mov(rbp, rdx))
        && has_asm64(bytes, |a| a.cmp(r12d, 0xFFFF))
        && has_asm64(bytes, |a| a.xor(sil, byte_ptr(rbp + rbx)))
        && has_asm64(bytes, |a| a.lea(rax, qword_ptr(rbx + 1)));
    Some(Evidence::required([
        (
            "websocket open-state check",
            has_asm64(bytes, |a| a.cmp(dword_ptr(rdi + 0x18), 2)),
        ),
        ("known frame argument and mask layout", old_shape || current_shape),
        (
            "websocket frame header buffer",
            has_asm64(bytes, |a| a.mov(ecx, 0x40)) && has_asm64(bytes, |a| a.mov(edx, 0x0E)),
        ),
        (
            "websocket opcode/length encoding",
            has_asm64(bytes, |a| a.and(esi, 0x0F))
                && has_asm64(bytes, |a| a.or(sil, 0x80)),
        ),
        ("masking key byte order", has_asm64(bytes, |a| a.bswap(eax))),
    ]))
}

fn validate_ccm_recv_pkt32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(ccm_recv_pkt32_evidence(code, offset), "ccm receive packet")
}

fn ccm_recv_pkt32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x190)?;
    Some(Evidence::required([
        ("receive mode argument", has_asm32(bytes, |a| a.push(1))),
        (
            "connection receive call",
            has_asm32_call_after(bytes, |a| a.push(1), 0x20),
        ),
        ("packet null check", has_asm32(bytes, |a| a.test(eax, eax))),
        (
            "packet status validation",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(esi + 0x04)))
                && has_x86_sub_eax_imm8(bytes, 1)
                && has_x86_cmp_eax_imm32(bytes, 0x00FF_FFFE),
        ),
        (
            "packet virtual consume",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(esi)))
                && has_asm32(bytes, |a| a.mov(edx, dword_ptr(eax + 0x08)))
                && (has_asm32(bytes, |a| a.call(dword_ptr(eax + 0x04)))
                    || has_asm32(bytes, |a| a.jmp(eax))),
        ),
    ]))
}

fn validate_ccm_recv_pkt64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(ccm_recv_pkt64_evidence(code, offset), "ccm receive packet")
}

fn ccm_recv_pkt64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x100)?;
    Some(Evidence::required([
        ("receive mode argument", has_asm64(bytes, |a| a.mov(esi, 1))),
        (
            "connection receive call",
            has_asm64_call_after(bytes, |a| a.mov(rdi, rbp), 0x10)
                || has_asm64_call_after(bytes, |a| a.mov(rdi, r12), 0x10),
        ),
        ("packet null check", has_asm64(bytes, |a| a.test(rax, rax))),
    ]))
}

fn validate_http_request_job_start32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        http_request_job_start32_evidence(code, offset),
        "manager/job/request start boundary",
    )
}

fn http_request_job_start32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    let classic_args = has_asm32(bytes, |a| a.mov(edi, dword_ptr(ebp + 0x08)))
        && has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x0C)))
        && has_asm32(bytes, |a| a.mov(edx, dword_ptr(ebp + 0x10)))
        && has_asm32(bytes, |a| a.mov(ebx, dword_ptr(ebp + 0x14)));
    let steamrt_args = has_asm32(bytes, |a| a.mov(edi, dword_ptr(ebp + 0x08)))
        && has_asm32(bytes, |a| a.mov(ebx, dword_ptr(ebp + 0x0C)))
        && has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x10)))
        && has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x14)));
    let classic_counter = has_asm32(bytes, |a| a.add(dword_ptr(edi + 0x38), 1))
        && has_asm32(bytes, |a| a.adc(dword_ptr(edi + 0x3C), 0));
    let steamrt_counter = has_asm32(bytes, |a| a.movq(xmm0, qword_ptr(edi + 0x38)))
        && has_seq(bytes, &[0x66, 0x0F, 0x6F, 0x8E])
        && has_asm32(bytes, |a| a.paddq(xmm0, xmm1))
        && has_asm32(bytes, |a| a.movq(qword_ptr(edi + 0x38), xmm0));
    Some(Evidence::required([
        (
            "cdecl manager/job/request arguments",
            classic_args || steamrt_args,
        ),
        (
            "manager outstanding increment",
            classic_counter || steamrt_counter,
        ),
        (
            "job start field",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(eax + 0x60)))
                || has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebx + 0x60))),
        ),
        (
            "job request flags",
            has_asm32(bytes, |a| a.or(byte_ptr(edx + 0x46), al))
                || has_asm32(bytes, |a| a.or(byte_ptr(ecx + 0x46), al)),
        ),
    ]))
}

fn validate_http_request_job_start64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        http_request_job_start64_evidence(code, offset),
        "manager/job/request start boundary",
    )
}

fn http_request_job_start64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    let classic_args = has_asm64(bytes, |a| a.mov(rbp, rsi))
        && has_asm64(bytes, |a| a.mov(rbx, rdi));
    let linux_args = has_asm64(bytes, |a| a.mov(r12, rsi))
        && has_asm64(bytes, |a| a.mov(rbp, rdi));
    Some(Evidence::required([
        ("manager and job arguments", classic_args || linux_args),
        (
            "request argument preservation",
            has_asm64(bytes, |a| a.mov(qword_ptr(rsp), rdx))
                || has_asm64(bytes, |a| a.mov(qword_ptr(rsp + 0x08), rdx)),
        ),
        (
            "manager outstanding increment",
            has_asm64(bytes, |a| a.add(qword_ptr(rdi + 0x40), 1)),
        ),
        (
            "job start field",
            has_asm64(bytes, |a| a.mov(r15, qword_ptr(rsi + 0x88))),
        ),
        (
            "job request flags",
            has_asm64(bytes, |a| a.or(byte_ptr(rbp + 0x52), r12b))
                || has_asm64(bytes, |a| a.or(byte_ptr(r12 + 0x52), al)),
        ),
    ]))
}

fn validate_mark_license_changed32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        mark_license_changed32_evidence(code, offset),
        "license-vector dirty mark",
    )
}

fn mark_license_changed32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x220)?;
    Some(Evidence::required([
        ("license vector load", has_x86_license_vector_load32(bytes)),
        (
            "dirty flag write",
            has_asm32(bytes, |a| a.mov(byte_ptr(esp + 0x1C), al)),
        ),
        ("license vector base", has_x86_license_vector_base32(bytes)),
        (
            "license id hash",
            has_asm32(bytes, |a| a.imul_3(edi, edi, 0x85EBCA6Bu32))
                || has_asm32(bytes, |a| a.imul_3(ebp, ebp, 0x85EBCA6Bu32)),
        ),
        (
            "license state hash table",
            (has_x86_rm32_disp32_load(bytes, 0x1ae4)
                && has_x86_rm32_disp32_load(bytes, 0x1af0)
                && has_x86_rm32_disp32_load(bytes, 0x1b04))
                || (has_x86_rm32_disp32_load(bytes, 0x1ae8)
                    && has_x86_rm32_disp32_load(bytes, 0x1af4)
                    && has_x86_rm32_disp32_load(bytes, 0x1b08)),
        ),
        (
            "package app-state lookup",
            has_x86_rm32_disp32_load(bytes, 0x0c58) && has_x86_rm32_disp32_load(bytes, 0x0c6c),
        ),
    ]))
}

fn validate_mark_license_changed64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        mark_license_changed64_evidence(code, offset),
        "license-vector dirty mark",
    )
}

fn mark_license_changed64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    let old_shape = has_asm64(bytes, |a| a.mov(ebx, esi))
        && has_asm64(bytes, |a| a.lea(rbp, qword_ptr(rax + 0xF20)))
        && has_asm64_call_after(bytes, |a| a.mov(esi, ebx), 0x20)
        && has_asm64(bytes, |a| a.mov(ecx, 6))
        && has_asm64(bytes, |a| a.mov(dword_ptr(rsp + 0x40), -1))
        && has_asm64(bytes, |a| a.mov(rdi, r12));
    let current_shape = has_asm64(bytes, |a| a.mov(ebp, esi))
        && has_asm64(bytes, |a| a.lea(r12, qword_ptr(rax + 0xF20)))
        && has_asm64_call_after(bytes, |a| a.mov(esi, ebp), 0x20)
        && has_asm64(bytes, |a| a.mov(ecx, 7))
        && has_asm64(bytes, |a| a.mov(dword_ptr(rsp), -1))
        && has_asm64(bytes, |a| a.mov(rdi, r13));
    Some(Evidence::required([
        ("known license-change layout", old_shape || current_shape),
        (
            "ownership recheck call",
            has_asm64(bytes, |a| a.test(al, al)),
        ),
    ]))
}

fn validate_process_pending_license_updates32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        process_pending_license_updates32_evidence(code, offset),
        "pending-license loop",
    )
}

fn process_pending_license_updates32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x220)?;
    Some(Evidence::required([
        (
            "pending-license count offset",
            has_x86_rm32_disp32_load(bytes, 0x1bd0) || has_x86_rm32_disp32_load(bytes, 0x1bd4),
        ),
        (
            "pending-license vector base",
            has_x86_rm32_disp32_load(bytes, 0x1bc4) || has_x86_rm32_disp32_load(bytes, 0x1bc8),
        ),
        (
            "pending-license entry stride",
            (has_asm32(bytes, |a| a.lea(ebx, dword_ptr(esi + esi * 8)))
                || has_asm32(bytes, |a| a.lea(esi, dword_ptr(edi + edi * 8))))
                && (has_asm32(bytes, |a| a.shl(ebx, 3)) || has_asm32(bytes, |a| a.shl(esi, 3))),
        ),
        (
            "pending-license status filter",
            has_asm32(bytes, |a| a.cmp(dword_ptr(eax + 0x14), 0x50)),
        ),
        (
            "license change mark call",
            has_asm32(bytes, |a| a.push(0))
                && has_asm32(bytes, |a| a.push(dword_ptr(eax)))
                && has_asm32_call_after(bytes, |a| a.push(dword_ptr(eax)), 0x20),
        ),
        (
            "removed entry compaction",
            has_x86_sub_eax_imm8(bytes, 1) && has_x86_push_edx_call_after(bytes, 0x20),
        ),
        (
            "changed-license followup",
            has_x86_rm32_disp32_load(bytes, 0x1b14) || has_x86_rm32_disp32_load(bytes, 0x1b18),
        ),
    ]))
}

fn validate_process_pending_license_updates64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        process_pending_license_updates64_evidence(code, offset),
        "pending-license loop",
    )
}

fn process_pending_license_updates64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x220)?;
    let old_package_iteration = has_asm64(bytes, |a| a.mov(edx, dword_ptr(r15 + 0x50)))
        && has_asm64(bytes, |a| a.mov(ebp, dword_ptr(rax + r14 * 4)))
        && has_asm64(bytes, |a| a.lea(r13, qword_ptr(rax + 0xF20)));
    let current_package_iteration = has_asm64(bytes, |a| a.mov(r8d, dword_ptr(r14 + 0x50)))
        && has_asm64(bytes, |a| a.mov(r12d, dword_ptr(rax + r15 * 4)))
        && has_asm64(bytes, |a| a.lea(r13, qword_ptr(rdi + 0xF20)));
    Some(Evidence::required([
        (
            "pending-license count offset",
            has_asm64(bytes, |a| a.mov(edx, dword_ptr(rdi + 0x2570))),
        ),
        (
            "pending-license vector base",
            has_asm64(bytes, |a| a.add(rax, 0x2560)),
        ),
        (
            "pending-license entry stride",
            has_asm64(bytes, |a| a.lea(rax, qword_ptr(rbx + rbx * 4)))
                && has_asm64(bytes, |a| a.shl(rax, 4)),
        ),
        (
            "license id load",
            has_asm64(bytes, |a| a.mov(esi, dword_ptr(rax)))
                && has_asm64(bytes, |a| a.cmp(esi, -1)),
        ),
        (
            "known package appid lookup layout",
            old_package_iteration || current_package_iteration,
        ),
        (
            "pending update state write",
            has_asm64(bytes, |a| a.mov(byte_ptr(rax + 0x233E), 0))
                || has_asm64(bytes, |a| a.mov(byte_ptr(rbx + 0x233E), 0)),
        ),
    ]))
}

fn validate_cutl_memory_grow32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        cutl_memory_grow32_evidence(code, offset),
        "cutlmemory<u32> grow",
    )
}

fn cutl_memory_grow32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;
    Some(Evidence::required([
        (
            "allocation pointer load",
            has_x86_mov_from_esi_disp8(bytes, 0x08),
        ),
        (
            "allocation count load",
            has_x86_mov_from_esi_disp8(bytes, 0x04),
        ),
        ("u32 element size", has_asm32(bytes, |a| a.push(4))),
        ("count scaled by u32", has_x86_shl_rm32_by_2(bytes)),
        (
            "allocation count store",
            has_asm32(bytes, |a| a.mov(dword_ptr(esi + 0x04), eax)),
        ),
        (
            "allocator vtable call",
            has_asm32(bytes, |a| a.call(dword_ptr(ebx + 0x18)))
                || has_asm32(bytes, |a| a.call(dword_ptr(ecx + 0x14))),
        ),
    ]))
}

fn validate_cutl_memory_grow64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(cutl_memory_grow64_evidence(code, offset), "cutlmemory grow")
}

fn cutl_memory_grow64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;
    let old_shape = has_asm64(bytes, |a| a.mov(r12d, esi))
        && has_asm64(bytes, |a| a.lea(rsi, qword_ptr(rax * 4)))
        && (has_asm64(bytes, |a| a.call(qword_ptr(r11 + 0x30)))
            || has_asm64(bytes, |a| a.call(qword_ptr(r11 + 0x28))));
    let current_shape = has_asm64(bytes, |a| a.mov(ebp, esi))
        && has_asm64(bytes, |a| a.shl(rdx, 2))
        && has_asm64(bytes, |a| a.shl(rsi, 2))
        && has_asm64(bytes, |a| a.call(qword_ptr(rax + 0x30)))
        && has_asm64(bytes, |a| a.call(qword_ptr(rax + 0x28)));
    Some(Evidence::required([
        (
            "CUtlMemory receiver save",
            has_asm64(bytes, |a| a.mov(rbx, rdi)),
        ),
        (
            "known allocator layout",
            old_shape || current_shape,
        ),
        (
            "allocation count/capacity loads",
            has_asm64(bytes, |a| a.mov(esi, dword_ptr(rbx + 0x0C)))
                && has_asm64(bytes, |a| a.mov(edi, dword_ptr(rbx + 0x08))),
        ),
        ("u32 element size", has_asm64(bytes, |a| a.mov(ecx, 4))),
        (
            "allocation count store",
            has_asm64(bytes, |a| a.mov(dword_ptr(rbx + 0x08), eax)),
        ),
        (
            "allocation pointer store",
            has_asm64(bytes, |a| a.mov(qword_ptr(rbx), rax)),
        ),
    ]))
}

fn validate_write_vdf_file32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(write_vdf_file32_evidence(code, offset), "vdf write path")
}

fn write_vdf_file32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    Some(Evidence::required([
        (
            "write size cap",
            has_asm32(bytes, |a| a.cmp(esi, 0x06400000)),
        ),
        (
            "write buffer object",
            has_asm32(bytes, |a| a.lea(ecx, dword_ptr(esp + 0x14)))
                && has_asm32(bytes, |a| a.mov(dword_ptr(esp + 0x14), 0)),
        ),
        (
            "optional compression path",
            has_asm32(bytes, |a| a.test(esi, esi)) && has_asm32(bytes, |a| a.test(edi, edi)),
        ),
        (
            "vdf write flags",
            has_asm32(bytes, |a| {
                a.push(1)?;
                a.push(0)?;
                a.push(1)?;
                a.push(0)?;
                a.push(0)
            }),
        ),
        (
            "VDF write dispatch",
            has_asm32_call_after(
                bytes,
                |a| {
                    a.push(1)?;
                    a.push(0)?;
                    a.push(1)?;
                    a.push(0)?;
                    a.push(0)
                },
                0x40,
            ),
        ),
    ]))
}

fn validate_write_vdf_file64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(write_vdf_file64_evidence(code, offset), "vdf write path")
}

fn write_vdf_file64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    let old_shape = has_asm64(bytes, |a| a.mov(rdi, r15))
        && has_asm64(bytes, |a| a.lea(rbx, qword_ptr(rsp + 0x20)))
        && has_asm64(bytes, |a| a.mov(rdi, r12))
        && has_asm64_call_after(
            bytes,
            |a| {
                a.mov(rcx, rax)?;
                a.mov(edx, r14d)
            },
            0x40,
        );
    let current_shape = has_asm64(bytes, |a| a.mov(rdi, r12))
        && has_asm64(bytes, |a| a.lea(rbx, qword_ptr(rsp + 0x10)))
        && has_asm64(bytes, |a| a.mov(rdi, r13))
        && has_asm64_call_after(
            bytes,
            |a| {
                a.mov(rdi, r13)?;
                a.mov(rcx, r14)
            },
            0x40,
        );
    Some(Evidence::required([
        (
            "write size cap",
            has_asm64(bytes, |a| a.cmp(r9d, 0x06400000)),
        ),
        (
            "known VDF writer layout",
            old_shape || current_shape,
        ),
        ("write flag argument", has_asm64(bytes, |a| a.push(1))),
    ]))
}

fn validate_spawn_process32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(spawn_process32_evidence(code, offset), "spawn process args")
}

fn spawn_process32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x220)?;
    Some(Evidence::required([
        (
            "spawn launch-info argument",
            has_asm32(bytes, |a| a.mov(esi, dword_ptr(ebp + 0x18))),
        ),
        (
            "game id discriminator",
            has_asm32(bytes, |a| a.cmp(byte_ptr(esi + 0x03), 2))
                && has_asm32(bytes, |a| a.and(eax, 0x00FF_FFFF))
                && has_asm32(bytes, |a| a.cmp(eax, 0x31673)),
        ),
        (
            "launch context allocation",
            has_asm32_call_after(bytes, |a| a.push(0x94), 0x20),
        ),
        (
            "launch context init",
            has_asm32(bytes, |a| a.mov(dword_ptr(edx + 0x90), -1))
                || has_asm32(bytes, |a| a.mov(dword_ptr(edx + 0xC0), -1)),
        ),
        (
            "environment block builder call",
            has_asm32(bytes, |a| a.push(dword_ptr(ebp + 0x24)))
                && has_asm32(bytes, |a| a.push(1))
                && has_asm32_call_after(bytes, |a| a.push(dword_ptr(ebp + 0x24)), 0x80),
        ),
    ]))
}

fn validate_spawn_process64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(spawn_process64_evidence(code, offset), "spawn process args")
}

fn spawn_process64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x240)?;
    let old_shape = has_asm64(bytes, |a| a.mov(r15, rdi))
        && has_asm64(bytes, |a| a.mov(rbx, rsi))
        && has_asm64(bytes, |a| a.mov(r12, r8))
        && has_asm64_call_after(bytes, |a| a.mov(r8, r12), 0x10);
    let current_shape = has_asm64(bytes, |a| a.mov(r14, rdi))
        && has_asm64(bytes, |a| a.mov(rbx, r8))
        && has_asm64(bytes, |a| a.mov(r8, r15));
    Some(Evidence::required([
        (
            "known spawn argument layout",
            old_shape || current_shape,
        ),
        (
            "game id discriminator",
            has_asm64(bytes, |a| a.cmp(byte_ptr(r8 + 0x03), 2))
                && has_asm64(bytes, |a| a.cmp(eax, 0x31673)),
        ),
        (
            "launch context allocation",
            has_asm64(bytes, |a| a.mov(edi, 0xC8))
                && (has_asm64(bytes, |a| a.mov(dword_ptr(rdx + 0xC0), -1))
                    || has_asm64(bytes, |a| a.mov(dword_ptr(r12 + 0xC0), -1))),
        ),
        (
            "environment block builder call",
            has_asm64(bytes, |a| a.push(1))
                && has_asm64(bytes, |a| a.mov(r9d, dword_ptr(rbp + 0x18)))
                && has_x64_push_rbp_negative_local_before_call(bytes),
        ),
    ]))
}

fn validate_build_spawn_env_block32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        build_spawn_env_block32_evidence(code, offset),
        "spawn env builder",
    )
}

fn build_spawn_env_block32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x320)?;
    Some(Evidence::required([
        (
            "env output arguments",
            (has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x20)))
                || has_asm32(bytes, |a| a.mov(ebx, dword_ptr(ebp + 0x20))))
                && (has_asm32(bytes, |a| a.mov(ecx, dword_ptr(ebp + 0x24)))
                    || has_asm32(bytes, |a| a.mov(edx, dword_ptr(ebp + 0x24)))),
        ),
        (
            "env source flags",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(ebp + 0x18)))
                && has_x86_and_eax_imm8(bytes, 1)
                && has_x86_test_ebp_disp8_imm8(bytes, 0x18, 2),
        ),
        (
            "game id parsing",
            ((has_asm32(bytes, |a| a.cmp(byte_ptr(edi + 0x03), 2))
                && (has_asm32(bytes, |a| a.movzx(eax, byte_ptr(edi + 0x01)))
                    || has_asm32(bytes, |a| a.movzx(edx, byte_ptr(edi + 0x01)))))
                || (has_asm32(bytes, |a| a.cmp(byte_ptr(esi + 0x03), 2))
                    && has_asm32(bytes, |a| a.movzx(eax, byte_ptr(esi + 0x01)))))
                && has_asm32(bytes, |a| a.shl(eax, 0x10)),
        ),
        (
            "env vector construction",
            has_asm32_call_after(bytes, |a| a.push(-1), 0x30)
                && has_asm32(bytes, |a| a.push(0x7FFF_FFFF)),
        ),
        (
            "fixed env block reservation",
            has_asm32_call_after(bytes, |a| a.push(0x5D), 0x30),
        ),
    ]))
}

fn validate_build_spawn_env_block64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        build_spawn_env_block64_evidence(code, offset),
        "spawn env builder",
    )
}

fn build_spawn_env_block64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x220)?;
    let old_shape = has_asm64(bytes, |a| a.mov(rax, qword_ptr(rbp + 0x10)))
        && has_asm64(bytes, |a| a.mov(r14, qword_ptr(rbp + 0x18)))
        && has_asm64(bytes, |a| a.mov(qword_ptr(rbp - 0x31F0), rsi))
        && has_asm64(bytes, |a| a.mov(qword_ptr(rbp - 0x31E8), rcx))
        && has_asm64(bytes, |a| a.mov(byte_ptr(rbp - 0x3100), 0));
    let current_shape = has_asm64(bytes, |a| a.mov(rax, qword_ptr(rbp + 0x18)))
        && has_asm64(bytes, |a| a.mov(r13, qword_ptr(rbp + 0x10)))
        && has_asm64(bytes, |a| a.mov(qword_ptr(rbp - 0x31A8), rsi))
        && has_asm64(bytes, |a| a.mov(qword_ptr(rbp - 0x31A0), rcx))
        && has_asm64(bytes, |a| a.mov(byte_ptr(rbp - 0x3040), 0));
    Some(Evidence::required([
        (
            "known spawn environment layout",
            old_shape || current_shape,
        ),
        (
            "Steam launch id formatting",
            has_asm64(bytes, |a| a.mov(r8d, 0x2F)) && has_asm64(bytes, |a| a.mov(esi, 0x1000)),
        ),
        (
            "env vector append",
            has_asm64_call_after(bytes, |a| a.mov(edx, -1), 0x40),
        ),
    ]))
}

fn validate_set_env_string32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(set_env_string32_evidence(code, offset), "env map insertion")
}

fn set_env_string32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    Some(Evidence::required([
        (
            "environment map load",
            has_x86_mov_from_any_disp8(bytes, 0x78),
        ),
        ("setenv key hash", has_asm32(bytes, |a| a.push(0x417))),
        ("insert mode argument", has_asm32(bytes, |a| a.push(1))),
    ]))
}

fn validate_set_env_string64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(set_env_string64_evidence(code, offset), "env map insertion")
}

fn set_env_string64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x180)?;
    let old_shape = has_asm64(bytes, |a| a.mov(eax, dword_ptr(r15 + 0xA4)))
        && has_asm64(bytes, |a| a.lea(r14, qword_ptr(r15 + 0x80)));
    let current_shape = has_asm64(bytes, |a| a.mov(eax, dword_ptr(rdi + 0xA4)))
        && has_asm64(bytes, |a| a.lea(r14, qword_ptr(r13 + 0x80)));
    Some(Evidence::required([
        (
            "known environment map layout",
            old_shape || current_shape,
        ),
        ("insert mode argument", has_asm64(bytes, |a| a.mov(ecx, 1))),
    ]))
}

fn validate_steamui_run_frame32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(steamui_run_frame32_evidence(code, offset), "ui frame tick")
}

fn steamui_run_frame32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;
    Some(Evidence::required([
        ("frame time store", has_x86_fstp_esp_disp8(bytes, 0x0C)),
        (
            "app controller state load",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(eax + 0xB70))),
        ),
    ]))
}

fn validate_steamui_run_frame64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(steamui_run_frame64_evidence(code, offset), "ui frame tick")
}

fn steamui_run_frame64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;
    Some(Evidence::required([
        (
            "frame time virtual call",
            has_asm64(bytes, |a| a.call(qword_ptr(rax + 0x28)))
                && has_x64_movsd_rbp_disp32_from_xmm0(bytes, -0x1240),
        ),
        (
            "app controller update calls",
            has_asm64(bytes, |a| a.call(qword_ptr(rax + 0x58)))
                && has_asm64(bytes, |a| a.call(qword_ptr(rax + 0x150))),
        ),
        (
            "frame-time comparison",
            has_asm64(bytes, |a| a.comisd(xmm0, qword_ptr(rbp - 0x1240))),
        ),
        (
            "controller active flag",
            has_asm64(bytes, |a| a.cmp(byte_ptr(rbx + 0x20), 0)),
        ),
    ]))
}

fn validate_fill_in_app_overview32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        fill_in_app_overview32_evidence(code, offset),
        "steam app layout fill",
    )
}

fn fill_in_app_overview32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let layout = discover_steam_app32_layout(code, offset);
    let mut evidence = Evidence::default();
    evidence.require("CSteamApp layout discovered", layout.is_some());
    if let Some(layout) = layout {
        evidence.require("game_id offset 0x04", layout.game_id_off == 0x04);
        evidence.require("app_id offset 0x0c", layout.app_id_off == 0x0c);
        evidence.require(
            "purchased_time offset 0x28",
            layout.purchased_time_off == 0x28,
        );
    }
    Some(evidence)
}

fn validate_fill_in_app_overview64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        fill_in_app_overview64_evidence(code, offset),
        "steam app layout fill",
    )
}

fn fill_in_app_overview64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let layout = discover_steam_app64_layout(code, offset);
    let mut evidence = Evidence::default();
    evidence.require("CSteamApp layout discovered", layout.is_some());
    if let Some(layout) = layout {
        evidence.require("game_id offset 0x08", layout.game_id_off == 0x08);
        evidence.require("app_id offset 0x10", layout.app_id_off == 0x10);
        evidence.require(
            "purchased_time offset 0x2c",
            layout.purchased_time_off == 0x2c,
        );
    }
    Some(evidence)
}

fn validate_build_complete_app_overview_change32(
    code: &[u8],
    offset: usize,
) -> Option<&'static str> {
    evidence_result(
        build_complete_app_overview_change32_evidence(code, offset),
        "overview change layout",
    )
}

fn build_complete_app_overview_change32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let layout = discover_app_overview_change32_layout(code, offset);
    let mut evidence = Evidence::default();
    evidence.require("CAppOverviewChange layout discovered", layout.is_some());
    if let Some(layout) = layout {
        evidence.require("app_overview offset 0x10", layout.app_overview_off == 0x10);
        evidence.require(
            "removed_appid offset 0x1c",
            layout.removed_appid_off == 0x1c,
        );
    }
    Some(evidence)
}

fn validate_build_complete_app_overview_change64(
    code: &[u8],
    offset: usize,
) -> Option<&'static str> {
    evidence_result(
        build_complete_app_overview_change64_evidence(code, offset),
        "overview change layout",
    )
}

fn build_complete_app_overview_change64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let layout = discover_app_overview_change64_layout(code, offset);
    let mut evidence = Evidence::default();
    evidence.require("CAppOverviewChange layout discovered", layout.is_some());
    if let Some(layout) = layout {
        evidence.require("app_overview offset 0x18", layout.app_overview_off == 0x18);
        evidence.require(
            "removed_appid offset 0x28",
            layout.removed_appid_off == 0x28,
        );
    }
    Some(evidence)
}

fn validate_get_app_by_id32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(get_app_by_id32_evidence(code, offset), "app lookup")
}

fn get_app_by_id32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x100)?;
    Some(Evidence::required([
        (
            "appid argument load",
            has_asm32(bytes, |a| a.mov(ebx, dword_ptr(ebp + 0x10))),
        ),
        (
            "receiver argument load",
            has_asm32(bytes, |a| a.mov(esi, dword_ptr(ebp + 0x08))),
        ),
        (
            "app map load",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(eax + 0x9E0))),
        ),
    ]))
}

fn validate_get_app_by_id64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(get_app_by_id64_evidence(code, offset), "app lookup")
}

fn get_app_by_id64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x100)?;
    Some(Evidence::required([
        ("appid stack spill", has_x64_stack_spill_r32(bytes, 6)),
        ("lookup mode stack spill", has_x64_stack_spill_r32(bytes, 2)),
        (
            "app entry null check",
            has_asm64(bytes, |a| {
                a.mov(eax, dword_ptr(rax))?;
                a.test(eax, eax)
            }),
        ),
    ]))
}

fn validate_mark_app_change32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        mark_app_change32_evidence(code, offset),
        "library change mark",
    )
}

fn mark_app_change32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x120)?;
    Some(Evidence::required([
        (
            "library app map load",
            has_asm32(bytes, |a| a.mov(eax, dword_ptr(eax + 0x9E0))),
        ),
        (
            "change flag materialization",
            has_asm32(bytes, |a| a.sete(cl)),
        ),
    ]))
}

fn validate_mark_app_change64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        mark_app_change64_evidence(code, offset),
        "library change mark",
    )
}

fn mark_app_change64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;
    Some(Evidence::required([
        ("change kind filter", has_asm64(bytes, |a| a.cmp(edi, 7))),
        (
            "library app map load",
            has_asm64(bytes, |a| a.mov(rdi, qword_ptr(rax + 0xB58))),
        ),
        ("app object save", has_asm64(bytes, |a| a.mov(r12, rax))),
    ]))
}

fn validate_repeated_field_add32(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        repeated_field_add32_evidence(code, offset),
        "repeated-field add abi",
    )
}

fn repeated_field_add32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x120)?;
    Some(Evidence::required([
        (
            "field size/capacity check",
            has_asm32(bytes, |a| {
                a.mov(esi, dword_ptr(ebx))?;
                a.cmp(esi, dword_ptr(ebx + 0x04))
            }),
        ),
        (
            "append slot write",
            has_asm32(bytes, |a| a.lea(edi, dword_ptr(esi + 0x01)))
                || has_asm32(bytes, |a| a.mov(dword_ptr(eax + esi * 4), edx)),
        ),
    ]))
}

fn validate_repeated_field_add64(code: &[u8], offset: usize) -> Option<&'static str> {
    evidence_result(
        repeated_field_add64_evidence(code, offset),
        "repeated-field add abi",
    )
}

fn repeated_field_add64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;
    Some(Evidence::required([
        (
            "field size/capacity check",
            has_asm64(bytes, |a| {
                a.mov(eax, dword_ptr(rdi + 0x04))?;
                a.cmp(dword_ptr(rdi), eax)
            }),
        ),
        (
            "field size increment",
            has_asm64(bytes, |a| {
                a.lea(edx, dword_ptr(rax + 0x01))?;
                a.mov(dword_ptr(rbp), edx)
            }),
        ),
        (
            "append slot write",
            has_asm64(bytes, |a| a.mov(dword_ptr(r8 + rax * 4), edx)),
        ),
    ]))
}

fn find_x64_rbp_dword_or_qword_load(bytes: &[u8], expected_disp: u8) -> Option<usize> {
    let has_mov_eax = bytes
        .windows(3)
        .any(|w| w[0] == 0x8b && w[1] == 0x45 && w[2] == expected_disp);
    let has_mov_r32 = bytes.windows(4).any(|w| {
        w[0] == 0x44 && w[1] == 0x8b && (0x40..=0x7f).contains(&w[2]) && w[3] == expected_disp
    });
    let has_mov_rax = bytes
        .windows(4)
        .any(|w| w == [0x48, 0x8b, 0x45, expected_disp]);
    (has_mov_eax || has_mov_r32 || has_mov_rax).then_some(expected_disp as usize)
}

fn find_x86_any_reg_disp8_load(bytes: &[u8], expected_disp: u8) -> Option<usize> {
    bytes
        .windows(3)
        .any(|w| w[0] == 0x8b && (0x40..=0x7f).contains(&w[1]) && w[2] == expected_disp)
        .then_some(expected_disp as usize)
}

fn find_x86_steam_app_game_id_load(bytes: &[u8]) -> Option<usize> {
    let high_then_low = bytes
        .windows(6)
        .any(|w| w == [0x8b, 0x50, 0x08, 0x8b, 0x40, 0x04]);
    let low_then_high = bytes
        .windows(6)
        .any(|w| w == [0x8b, 0x40, 0x04, 0x8b, 0x50, 0x08]);
    (high_then_low || low_then_high).then_some(0x04)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageMapLayout {
    count_off: usize,
    elements_off: usize,
    node_size: usize,
    node_key_off: usize,
    node_value_off: usize,
}

fn scan_steamclient64_layouts(code: &[u8], vaddr: u64, resolved: &HashMap<&str, usize>) -> bool {
    let mut failed = false;
    failed |= scan_semantic_checks(
        code,
        vaddr,
        resolved,
        STEAMCLIENT64_SEMANTIC_CHECKS,
        SemanticArch::X86_64,
    );

    if let Some(&get_package_info_offset) = resolved.get("CPackageInfo::GetPackageInfo") {
        match discover_package_info64_layout(code, get_package_info_offset) {
            Some(layout) => {
                println!(
                    "  OK   {:<58} root=0x{:x} elements=0x{:x} node=0x{:x} key=0x{:x} value=0x{:x}",
                    "CPackageInfo::GetPackageInfo token map",
                    layout.count_off,
                    layout.elements_off,
                    layout.node_size,
                    layout.node_key_off,
                    layout.node_value_off
                );
            }
            None => {
                let evidence = package_info64_evidence(code, get_package_info_offset);
                print_evidence_failure(
                    "CPackageInfo::GetPackageInfo token map",
                    vaddr + get_package_info_offset as u64,
                    evidence.as_ref(),
                    "layout discovery failed",
                );
                failed = true;
            }
        }
    }

    failed
}

fn scan_steamclient32_layouts(code: &[u8], vaddr: u64, resolved: &HashMap<&str, usize>) -> bool {
    let mut failed = false;
    failed |= scan_semantic_checks(
        code,
        vaddr,
        resolved,
        STEAMCLIENT32_SEMANTIC_CHECKS,
        SemanticArch::X86,
    );

    if let Some(&get_package_info_offset) = resolved.get("CPackageInfo::GetPackageInfo") {
        match discover_package_info32_layout(code, get_package_info_offset) {
            Some(layout) => {
                println!(
                    "  OK   {:<58} root=0x{:x} elements=0x{:x} node=0x{:x} key=0x{:x} value=0x{:x}",
                    "CPackageInfo::GetPackageInfo package map",
                    layout.count_off,
                    layout.elements_off,
                    layout.node_size,
                    layout.node_key_off,
                    layout.node_value_off
                );
            }
            None => {
                let evidence = package_info32_evidence(code, get_package_info_offset);
                print_evidence_failure(
                    "CPackageInfo::GetPackageInfo package map",
                    vaddr + get_package_info_offset as u64,
                    evidence.as_ref(),
                    "layout discovery failed",
                );
                failed = true;
            }
        }
    }

    failed
}

fn ticket_ext_data_mode4_thunk32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x160)?;

    let has_mode4 = has_asm32(bytes, |a| a.push(4));
    let adjusts_this_to_cuser =
        find_x86_sub_eax_imm32_matching(bytes, |imm| matches!(imm, 0x18d4 | 0x18d8)).is_some();
    let calls_shared_builder_after_mode = has_call_after_mode4_push(bytes);

    let mut evidence = Evidence::default();
    evidence.require("mode=4 argument", has_mode4);
    evidence.require("ClientUser to CUser adjustment", adjusts_this_to_cuser);
    evidence.require(
        "shared ticket builder call",
        calls_shared_builder_after_mode,
    );
    Some(evidence)
}

fn ticket_ext_data_mode4_thunk64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x100)?;

    let has_mode4 = has_asm64(bytes, |a| a.push(4));
    let adjusts_this_to_cuser = has_asm64(bytes, |a| a.lea(rdi, qword_ptr(r12 - 0x1FD0)))
        || has_asm64(bytes, |a| a.lea(rdi, qword_ptr(rbx - 0x1FD0)));
    let calls_shared_builder_after_mode = has_call_after_mode4_push(bytes);

    let mut evidence = Evidence::default();
    evidence.require("mode=4 argument", has_mode4);
    evidence.require("ClientUser to CUser adjustment", adjusts_this_to_cuser);
    evidence.require(
        "shared ticket builder call",
        calls_shared_builder_after_mode,
    );
    Some(evidence)
}

fn update_ticket32_evidence(
    code: &[u8],
    offset: usize,
    check_ownership_offset: usize,
) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x280)?;
    let has_force_arg_branch = has_asm32(bytes, |a| a.cmp(byte_ptr(ebp + 0x10), 0));
    let has_result_struct_init = has_asm32(bytes, |a| a.mov(ecx, 0x0D))
        && bytes
            .windows(7)
            .any(|w| w[0] == 0xc7 && w[1] == 0x45 && w[3..7] == [0xff, 0xff, 0xff, 0xff]);
    let calls_check_ownership =
        has_relative_call_to(code, offset, bytes.len(), check_ownership_offset);
    let receiver_is_valid = update_ticket32_has_valid_receiver(bytes);

    let mut evidence = Evidence::default();
    evidence.require("force argument branch", has_force_arg_branch);
    evidence.require("ownership result struct init", has_result_struct_init);
    evidence.require("CheckAppOwnership call", calls_check_ownership);
    evidence.require("CUser receiver layout", receiver_is_valid);
    Some(evidence)
}

fn update_ticket32_has_valid_receiver(bytes: &[u8]) -> bool {
    let receiver_adjust_window = &bytes[..bytes.len().min(0x100)];
    if find_x86_sub_eax_imm32_matching(receiver_adjust_window, |imm| {
        matches!(imm, 0x18d4 | 0x18d8)
            && has_x86_cmp_rm32_imm8(bytes, 0u32.wrapping_sub(imm - 0xf8), 0x04)
    })
    .is_some()
    {
        return true;
    }

    has_asm32(bytes, |a| a.cmp(dword_ptr(eax + 0xF8), 4))
}

fn update_ticket64_evidence(
    code: &[u8],
    offset: usize,
    check_ownership_offset: usize,
) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x330)?;
    let has_force_arg_branch = has_asm64(bytes, |a| a.test(dl, dl));
    let old_shape = has_asm64(bytes, |a| a.cmp(dword_ptr(rbx + 0x1E8), 4))
        && has_asm64(bytes, |a| a.mov(dword_ptr(rsp + 0x70), -1))
        && has_asm64(bytes, |a| a.mov(ecx, 6));
    let current_shape = has_asm64(bytes, |a| a.cmp(dword_ptr(rbx - 0x1DE8), 4))
        && has_asm64(bytes, |a| a.mov(dword_ptr(rsp + 0x20), -1))
        && has_asm64(bytes, |a| a.mov(ecx, 7));
    let calls_check_ownership =
        has_relative_call_to(code, offset, bytes.len(), check_ownership_offset);

    let mut evidence = Evidence::default();
    evidence.require("force argument branch", has_force_arg_branch);
    evidence.require("known ticket update layout", old_shape || current_shape);
    evidence.require("CheckAppOwnership call", calls_check_ownership);
    Some(evidence)
}

fn has_relative_call_to(
    code: &[u8],
    function_offset: usize,
    max_len: usize,
    target_offset: usize,
) -> bool {
    let end = code.len().min(function_offset.saturating_add(max_len));
    let mut cursor = function_offset;
    while cursor + 5 <= end {
        if code[cursor] == 0xe8
            && relative_call_target_offset(code, cursor)
                .is_some_and(|target| target == target_offset)
        {
            return true;
        }
        cursor += 1;
    }
    false
}

fn relative_call_target_offset(code: &[u8], call_offset: usize) -> Option<usize> {
    let disp: [u8; 4] = code
        .get(call_offset + 1..call_offset + 5)?
        .try_into()
        .ok()?;
    let target = call_offset as isize + 5 + i32::from_le_bytes(disp) as isize;
    (target >= 0 && (target as usize) < code.len()).then_some(target as usize)
}

fn has_call_after_mode4_push(bytes: &[u8]) -> bool {
    let Some(push_mode4) = asm_bytes32(|a| a.push(4)) else {
        return false;
    };
    bytes.windows(push_mode4.len()).enumerate().any(|(idx, w)| {
        w == push_mode4.as_slice()
            && bytes[idx + push_mode4.len()..bytes.len().min(idx + 0x30)].contains(&0xe8)
    })
}

fn is_user_subscribed_app_in_ticket32_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x1f0)?;

    let has_status_filter = has_asm32(bytes, |a| {
        a.and(edx, -3)?;
        a.cmp(edx, 1)
    });
    let has_no_entries_return = x86_has_stack_return_code(bytes, 2);
    let has_miss_return = x86_has_stack_return_code(bytes, 1);
    let has_hit_return = x86_has_stack_return_code(bytes, 0);
    let removes_ticket_entry = has_asm32(bytes, |a| a.mov(dword_ptr(ecx + 0x1884), eax));

    let mut evidence = Evidence::default();
    evidence.require("ticket status filter", has_status_filter);
    evidence.require("no-entry return code 2", has_no_entries_return);
    evidence.require("miss return code 1", has_miss_return);
    evidence.require("hit return code 0", has_hit_return);
    evidence.reject("ticket removal side effect", removes_ticket_entry);
    Some(evidence)
}

fn is_user_subscribed_app_in_ticket64_evidence(code: &[u8], offset: usize) -> Option<Evidence> {
    let bytes = bounded_tail(code, offset, 0x140)?;

    let has_status_filter = has_asm64(bytes, |a| {
        a.and(edx, -3)?;
        a.cmp(edx, 1)
    });
    let old_returns = has_asm64(bytes, |a| a.mov(esi, 2))
        && has_asm64(bytes, |a| a.mov(esi, 1))
        && has_asm64(bytes, |a| a.xor(esi, esi));
    let current_returns = has_asm64(bytes, |a| a.mov(r8d, 2))
        && has_asm64(bytes, |a| a.mov(r8d, 1))
        && has_asm64(bytes, |a| a.xor(r8d, r8d));
    let removes_ticket_entry = has_asm64(bytes, |a| a.mov(dword_ptr(r13 + 0x1F60), edx));

    let mut evidence = Evidence::default();
    evidence.require("ticket status filter", has_status_filter);
    evidence.require("known return-code layout", old_returns || current_returns);
    evidence.reject("ticket removal side effect", removes_ticket_entry);
    Some(evidence)
}

fn x86_has_stack_return_code(bytes: &[u8], value: u8) -> bool {
    bytes.windows(8).any(|w| {
        w[0] == 0xc7
            && w[1] == 0x44
            && w[2] == 0x24
            && w[4] == value
            && w[5] == 0x00
            && w[6] == 0x00
            && w[7] == 0x00
    })
}

fn discover_package_info32_layout(
    code: &[u8],
    get_package_info_offset: usize,
) -> Option<PackageMapLayout> {
    let bytes = code.get(get_package_info_offset..get_package_info_offset.saturating_add(0x240))?;

    // CPackageInfo::GetPackageInfo(this, package_id, access_token) must load
    // both halves of access_token from stack and search the package-id map.
    if !find_x86_get_package_info_args(bytes) {
        return None;
    }

    let root_off = find_x86_mov_eax_eax_disp8(bytes)?;
    let elements_off = find_x86_mov_edx_ebx_disp8(bytes)?;
    let node_size = find_x86_node_size(bytes)?;
    let node_key_off = find_x86_node_key_off(bytes)?;
    let node_value_off = find_x86_node_value_off(bytes)?;

    Some(PackageMapLayout {
        count_off: root_off,
        elements_off,
        node_size,
        node_key_off,
        node_value_off,
    })
}

fn package_info32_evidence(code: &[u8], get_package_info_offset: usize) -> Option<Evidence> {
    let bytes = code.get(get_package_info_offset..get_package_info_offset.saturating_add(0x240))?;
    let has_args = find_x86_get_package_info_args(bytes);
    let root_off = find_x86_mov_eax_eax_disp8(bytes);
    let elements_off = find_x86_mov_edx_ebx_disp8(bytes);
    let node_size = find_x86_node_size(bytes);
    let node_key_off = find_x86_node_key_off(bytes);
    let node_value_off = find_x86_node_value_off(bytes);

    let mut evidence = Evidence::default();
    evidence.require("package id and access token args", has_args);
    evidence.require("package map root offset", root_off.is_some());
    evidence.require("package map elements offset", elements_off.is_some());
    evidence.require("package map node size", node_size.is_some());
    evidence.require("package map key offset", node_key_off.is_some());
    evidence.require("package map value offset", node_value_off.is_some());
    Some(evidence)
}

fn discover_package_info64_layout(
    code: &[u8],
    get_package_info_offset: usize,
) -> Option<PackageMapLayout> {
    let bytes = code.get(get_package_info_offset..get_package_info_offset.saturating_add(0x120))?;
    let root_off = find_x64_movslq_rdi_disp32(bytes)?;
    let elements_off = find_x64_elements_load_from_rdi(bytes)?;
    let node_size = find_x64_node_size(bytes)?;
    let node_key_off = find_x64_node_key_off(bytes)?;
    let node_value_off =
        find_x64_inline_return_off(bytes).or_else(|| find_x64_pointer_return_off(bytes))?;

    Some(PackageMapLayout {
        count_off: root_off,
        elements_off,
        node_size,
        node_key_off,
        node_value_off,
    })
}

fn package_info64_evidence(code: &[u8], get_package_info_offset: usize) -> Option<Evidence> {
    let bytes = code.get(get_package_info_offset..get_package_info_offset.saturating_add(0x120))?;
    let root_off = find_x64_movslq_rdi_disp32(bytes);
    let elements_off = find_x64_elements_load_from_rdi(bytes);
    let node_size = find_x64_node_size(bytes);
    let node_key_off = find_x64_node_key_off(bytes);
    let node_value_off =
        find_x64_inline_return_off(bytes).or_else(|| find_x64_pointer_return_off(bytes));

    let mut evidence = Evidence::default();
    evidence.require("token map root offset", root_off.is_some());
    evidence.require("token map elements offset", elements_off.is_some());
    evidence.require("token map node size", node_size.is_some());
    evidence.require("token map key offset", node_key_off.is_some());
    evidence.require("token map value offset", node_value_off.is_some());
    Some(evidence)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<usize> {
    let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw) as usize)
}

fn find_x86_get_package_info_args(bytes: &[u8]) -> bool {
    let package_id = bytes.windows(3).any(|w| w == [0x8b, 0x75, 0x0c]);
    let token_stack_pair = bytes.windows(3).any(|w| w == [0x8b, 0x45, 0x10])
        && bytes.windows(3).any(|w| w == [0x8b, 0x55, 0x14]);
    let token_stack_xmm = bytes
        .windows(5)
        .any(|w| w == [0xf3, 0x0f, 0x7e, 0x4d, 0x10]);
    let token_compare_sse = bytes
        .windows(5)
        .any(|w| w == [0xf3, 0x0f, 0x7e, 0x47, 0x08]);
    let token_compare_scalar = bytes
        .windows(7)
        .any(|w| w == [0x8b, 0x43, 0x08, 0x33, 0x7b, 0x0c, 0x31]);
    package_id
        && (token_stack_pair || token_stack_xmm)
        && (token_compare_sse || token_compare_scalar)
}

fn find_x86_mov_eax_eax_disp8(bytes: &[u8]) -> Option<usize> {
    bytes
        .get(..0x80)?
        .windows(3)
        .find_map(|w| (w[0..2] == [0x8b, 0x40]).then_some(w[2] as usize))
}

fn find_x86_mov_edx_ebx_disp8(bytes: &[u8]) -> Option<usize> {
    bytes.get(..0x120)?.windows(3).find_map(|w| {
        matches!(
            &w[0..2],
            // mov edx,[ebx+disp]
            [0x8b, 0x53]
                // mov ebx,[ecx+disp]
                | [0x8b, 0x59]
                // mov ecx,[ebx+disp]
                | [0x8b, 0x4b]
                // mov ecx,[ecx+disp]
                | [0x8b, 0x49]
        )
        .then_some(w[2] as usize)
    })
}

fn find_x86_node_size(bytes: &[u8]) -> Option<usize> {
    if bytes
        .windows(6)
        .any(|w| w == [0x8d, 0x04, 0x40, 0x8d, 0x04, 0xc2])
    {
        return Some(0x18);
    }
    if bytes
        .windows(6)
        .any(|w| w == [0x8d, 0x04, 0x52, 0x8d, 0x04, 0xc3])
    {
        return Some(0x18);
    }
    if let Some(shift) = bytes
        .windows(6)
        .find_map(|w| (w[0..3] == [0x8d, 0x04, 0x40] && w[3..5] == [0xc1, 0xe0]).then_some(w[5]))
    {
        return 3usize.checked_shl(shift as u32);
    }
    bytes.windows(6).find_map(|w| {
        (w[0..3] == [0x8d, 0x1c, 0x5b] && w[3..5] == [0xc1, 0xe3])
            .then(|| 3usize.checked_shl(w[5] as u32))
            .flatten()
    })
}

fn find_x86_node_key_off(bytes: &[u8]) -> Option<usize> {
    bytes.windows(3).find_map(|w| {
        ((w[0..2] == [0x39, 0x70]) || (w[0..2] == [0x3b, 0x70])).then_some(w[2] as usize)
    })
}

fn find_x86_node_value_off(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(3)
        .find_map(|w| (w[0..2] == [0x8b, 0x78]).then_some(w[2] as usize))
        .or_else(|| {
            bytes
                .windows(4)
                .find_map(|w| (w[0..3] == [0x8b, 0x44, 0x03]).then_some(w[3] as usize))
        })
}

fn find_x64_movslq_rdi_disp32(bytes: &[u8]) -> Option<usize> {
    bytes.windows(7).enumerate().find_map(|(idx, w)| {
        (w[0..3] == [0x48, 0x63, 0x87])
            .then(|| read_u32_le(bytes, idx + 3))
            .flatten()
    })
}

fn find_x64_elements_load_from_rdi(bytes: &[u8]) -> Option<usize> {
    bytes.windows(7).enumerate().find_map(|(idx, w)| {
        (w[0..3] == [0x48, 0x8b, 0xbf] || w[0..3] == [0x48, 0x8b, 0x8f])
            .then(|| read_u32_le(bytes, idx + 3))
            .flatten()
    })
}

fn find_x64_node_size(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .find_map(|w| (w[0..3] == [0x48, 0x6b, 0xc0]).then_some(w[3] as usize))
        .or_else(|| {
            bytes.windows(7).find_map(|w| {
                (w[0..3] == [0x48, 0x69, 0xc0])
                    .then(|| u32::from_le_bytes([w[3], w[4], w[5], w[6]]) as usize)
            })
        })
        .or_else(|| {
            bytes.windows(4).find_map(|w| {
                (w[0..3] == [0x48, 0xc1, 0xe0])
                    .then(|| 1usize.checked_shl(w[3] as u32))
                    .flatten()
            })
        })
        .filter(|size| *size >= 0x20 && *size <= 0x100)
}

fn find_x64_node_key_off(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).find_map(|w| {
        ((w[0..3] == [0x48, 0x8b, 0x50]) || (w[0..3] == [0x48, 0x8b, 0x48]))
            .then_some(w[3] as usize)
            .or_else(|| {
                (w[0..3] == [0x48, 0x3b, 0x50] || w[0..3] == [0x48, 0x3b, 0x48])
                    .then_some(w[3] as usize)
            })
    })
}

fn find_x64_inline_return_off(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(5)
        .find_map(|w| (w[0..3] == [0x48, 0x83, 0xc0] && w[4] == 0xc3).then_some(w[3] as usize))
        .or_else(|| {
            bytes.windows(7).find_map(|w| {
                (w[0..2] == [0x48, 0x05] && w[6] == 0xc3)
                    .then(|| u32::from_le_bytes([w[2], w[3], w[4], w[5]]) as usize)
            })
        })
}

fn find_x64_pointer_return_off(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(5)
        .find_map(|w| (w[0..4] == [0x48, 0x8b, 0x44, 0x07]).then_some(w[4] as usize))
}
