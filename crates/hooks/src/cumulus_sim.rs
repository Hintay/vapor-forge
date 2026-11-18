//! Two-device stats refusal and merge simulation against a running Cumulus
//! server.
//!
//! The Steam-facing parts of this flow (the stats proxy and the achievement
//! worker) are Linux-only, so this test drives the layers they are built on in
//! the same order: the sync journal records the commit and the refusal, the
//! Cumulus backend uploads and reads stats, and `stats_merge` merges the
//! refused values into the authoritative state before the commit is rebuilt.
//!
//! Ignored by default; `scripts/cumulus-sim.sh` starts a throwaway server and
//! runs it with `CUMULUS_SIM_URL`, `CUMULUS_SIM_ADMIN_USER` and
//! `CUMULUS_SIM_ADMIN_PASSWORD` set.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use vapor_forge_cloud_core::{
    AchievementSchema, AppStatsQuery, AppStatsResult, AppStatsUploadResult, AppStatsUploadStatus,
    CloudBackend, DeviceDescriptor, OfficialAchievementState, OfficialStatState, StatsCommit,
    SteamAppSnapshot, UploadIdentity,
};
use vapor_forge_cloud_cumulus::{CumulusBackend, CumulusSettings};
use vapor_forge_sync_journal::SyncJournal;

const APP_ID: u32 = 630;
const STAT_ACHIEVEMENTS: u32 = 1;
const STAT_X: u32 = 2;
const STAT_Y: u32 = 3;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for the simulation"))
}

fn unique() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    (nanos % 1_000_000_000_000) * 100 + COUNTER.fetch_add(1, Ordering::Relaxed) % 100 + 1
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn admin_post(url: &str, cookie: Option<&str>, path: &str, body: Value) -> (Value, Option<String>) {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(20)))
        .http_status_as_error(false)
        .build()
        .new_agent();
    let mut request = agent
        .post(&format!("{url}{path}"))
        .header("Content-Type", "application/json");
    if let Some(cookie) = cookie {
        request = request.header("Cookie", cookie);
    }
    let mut response = request
        .send(serde_json::to_vec(&body).unwrap().as_slice())
        .unwrap();
    let cookie = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("cml_session="))
        .and_then(|value| value.split(';').next())
        .map(str::to_string);
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    assert!(
        (200..300).contains(&status),
        "{path}: HTTP {status}: {text}"
    );
    (serde_json::from_str(&text).unwrap(), cookie)
}

/// Provision a fresh user with two device keys through the admin API.
fn provision(label: &str) -> (String, String) {
    let url = env("CUMULUS_SIM_URL");
    let (_, cookie) = admin_post(
        &url,
        None,
        "/admin/api/login",
        json!({
            "username": env("CUMULUS_SIM_ADMIN_USER"),
            "password": env("CUMULUS_SIM_ADMIN_PASSWORD"),
        }),
    );
    let cookie = cookie.expect("admin session cookie");
    let name = format!("sim-{label}-{}", unique());
    let (user, _) = admin_post(
        &url,
        Some(&cookie),
        "/admin/api/users",
        json!({
            "name": name,
            "email": format!("{name}@example.test"),
            "password": "SimPassphrase!2026-member",
        }),
    );
    let user_id = user["id"].as_i64().unwrap();
    let token = || {
        admin_post(
            &url,
            Some(&cookie),
            &format!("/admin/api/users/{user_id}/tokens"),
            json!({ "label": "simulation" }),
        )
        .0["token"]
            .as_str()
            .unwrap()
            .to_string()
    };
    (token(), token())
}

fn kv_string(out: &mut Vec<u8>, key: &str, value: &str) {
    out.push(1);
    out.extend_from_slice(key.as_bytes());
    out.push(0);
    out.extend_from_slice(value.as_bytes());
    out.push(0);
}

fn kv_object(out: &mut Vec<u8>, key: &str, body: impl FnOnce(&mut Vec<u8>)) {
    out.push(0);
    out.extend_from_slice(key.as_bytes());
    out.push(0);
    body(out);
    out.push(8);
}

fn kv_int(out: &mut Vec<u8>, key: &str, value: i32) {
    out.push(2);
    out.extend_from_slice(key.as_bytes());
    out.push(0);
    out.extend_from_slice(&value.to_le_bytes());
}

/// Binary KeyValues stats schema: achievement block 1 and integer stats 2, 3.
fn schema() -> Vec<u8> {
    let mut schema = Vec::new();
    kv_object(&mut schema, &APP_ID.to_string(), |root| {
        kv_object(root, "stats", |stats| {
            kv_object(stats, &STAT_ACHIEVEMENTS.to_string(), |stat| {
                kv_int(stat, "type", 4);
                kv_object(stat, "bits", |bits| {
                    kv_object(bits, "0", |entry| {
                        kv_string(entry, "name", "ACH_WIN");
                        kv_object(entry, "display", |display| {
                            kv_object(display, "name", |names| {
                                kv_string(names, "english", "Winner");
                            });
                        });
                    });
                });
            });
            kv_object(stats, &STAT_X.to_string(), |stat| {
                kv_string(stat, "name", "STAT_X");
                kv_int(stat, "type", 1);
            });
            kv_object(stats, &STAT_Y.to_string(), |stat| {
                kv_string(stat, "name", "STAT_Y");
                kv_int(stat, "type", 1);
            });
        });
    });
    schema
}

/// Steam's local stats cache on one device.
#[derive(Clone, Debug)]
struct LocalCache {
    unlocked_at: Option<i64>,
    x: String,
    y: String,
}

impl LocalCache {
    fn achievements(&self) -> Vec<OfficialAchievementState> {
        vec![OfficialAchievementState {
            key: "ACH_WIN".into(),
            unlocked: self.unlocked_at.is_some(),
            unlocked_at: self.unlocked_at,
        }]
    }

    fn stats(&self) -> Vec<OfficialStatState> {
        [("STAT_X", &self.x), ("STAT_Y", &self.y)]
            .into_iter()
            .map(|(key, value)| OfficialStatState {
                key: key.into(),
                value_type: "int".into(),
                value: value.clone(),
            })
            .collect()
    }

    /// Steam's cache after it applied a GetUserStats response built from
    /// `result`.
    fn from_result(result: &AppStatsResult) -> Self {
        let AppStatsResult::Modified {
            achievements,
            stats,
            ..
        } = result
        else {
            panic!("expected authoritative state, got {result:?}");
        };
        let stat = |key: &str| {
            stats
                .iter()
                .find(|stat| stat.stat_key == key)
                .map(|stat| stat.value.clone())
                .unwrap_or_default()
        };
        Self {
            unlocked_at: achievements
                .iter()
                .find(|achievement| {
                    achievement.achievement_key == "ACH_WIN" && achievement.unlocked
                })
                .map(|achievement| achievement.unlocked_at.unwrap_or_default()),
            x: stat("STAT_X"),
            y: stat("STAT_Y"),
        }
    }
}

struct Device {
    backend: CumulusBackend,
    client_id: u64,
    steam_id64: String,
    scope: String,
}

impl Device {
    fn new(token: String, steam_id64: &str) -> Self {
        let client_id = unique();
        let backend = CumulusBackend::new(CumulusSettings {
            server_url: env("CUMULUS_SIM_URL"),
            token,
            timeout_connect_ms: 5_000,
            timeout_ms: 20_000,
        });
        backend
            .ensure_device_bound(&DeviceDescriptor {
                client_id,
                machine_name: format!("sim-{client_id}"),
                os_type: None,
                device_type: None,
            })
            .expect("device binds");
        let scope = backend.principal_scope(Some(client_id)).unwrap();
        Self {
            backend,
            client_id,
            steam_id64: steam_id64.to_string(),
            scope,
        }
    }

    fn identity(&self) -> UploadIdentity {
        UploadIdentity {
            client_id: self.client_id,
            machine_name: format!("sim-{}", self.client_id),
            os_type: None,
            device_type: None,
            steam_id64: self.steam_id64.clone(),
            persona_name: None,
        }
    }

    fn snapshot(
        &self,
        commit_id: &str,
        base_crc_stats: Option<u32>,
        dirty_stat_ids: &[u32],
        cache: &LocalCache,
    ) -> SteamAppSnapshot {
        SteamAppSnapshot {
            owner_scope: self.scope.clone(),
            owner_steam_id64: self.steam_id64.clone(),
            commit_id: commit_id.into(),
            app_id: APP_ID,
            base_crc_stats,
            dirty_stat_ids: dirty_stat_ids.to_vec(),
            achievements: cache.achievements(),
            stats: cache.stats(),
            observed_at: now(),
        }
    }

    fn upload(&self, snapshot: &SteamAppSnapshot) -> AppStatsUploadResult {
        self.backend
            .upload_steam_app_snapshot(&self.identity(), snapshot)
            .expect("stats upload")
            .stats_apps
            .into_iter()
            .find(|app| app.app_id == APP_ID)
            .expect("upload result names the app")
    }

    fn pull(&self, client_crc_stats: Option<u32>) -> AppStatsResult {
        self.backend
            .pull_app_stats(
                self.client_id,
                &self.steam_id64,
                &AppStatsQuery {
                    app_id: APP_ID,
                    client_crc_stats,
                    schema_version: format!("{:x}", Sha256::digest(schema())),
                },
            )
            .expect("user-stats read")
    }
}

/// Bring two devices of one account to the point where A uploads a stale
/// commit: the server holds A's earlier x and B's newer y and unlock, while A's
/// cache still holds the old y and a locked achievement plus its new x.
struct Refusal {
    a: Device,
    a_cache: LocalCache,
    a_base: Option<u32>,
}

fn prepare(label: &str) -> Refusal {
    let (token_a, token_b) = provision(label);
    let steam_id64 = (76_561_197_960_265_728 + unique() % 1_000_000_000).to_string();
    let a = Device::new(token_a, &steam_id64);
    let b = Device::new(token_b, &steam_id64);
    let content = schema();
    a.backend
        .upload_achievement_schema(
            a.client_id,
            &AchievementSchema {
                owner_scope: a.scope.clone(),
                app_id: APP_ID,
                language: "english".into(),
                schema_version: Some(format!("{:x}", Sha256::digest(&content))),
                content,
            },
        )
        .expect("schema upload");

    let initial = LocalCache {
        unlocked_at: None,
        x: "1".into(),
        y: "1".into(),
    };
    let first = a.upload(&a.snapshot("a-0", None, &[STAT_X, STAT_Y], &initial));
    assert_eq!(first.status, AppStatsUploadStatus::Uninitialized);
    let a_base = first.crc_stats;

    // B starts from the server state and changes y and the achievement.
    let b_base = match b.pull(None) {
        AppStatsResult::Modified { crc_stats, .. } => crc_stats,
        other => panic!("B reads the authoritative state: {other:?}"),
    };
    assert_eq!(b_base, a_base);
    let b_cache = LocalCache {
        unlocked_at: Some(1_800_000_000),
        x: "1".into(),
        y: "5".into(),
    };
    let applied = b.upload(&b.snapshot("b-1", b_base, &[STAT_ACHIEVEMENTS, STAT_Y], &b_cache));
    assert_eq!(applied.status, AppStatsUploadStatus::Applied);
    assert_ne!(applied.crc_stats, a_base);

    // A changed x on top of its outdated cache.
    Refusal {
        a,
        a_cache: LocalCache {
            x: "10".into(),
            ..initial
        },
        a_base,
    }
}

fn final_state(device: &Device) -> LocalCache {
    LocalCache::from_result(&device.pull(None))
}

#[test]
#[ignore = "needs a running Cumulus server; see scripts/cumulus-sim.sh"]
fn cumulus_sim_6_refused_stats_merge_keeps_both_devices_values() {
    let Refusal { a, a_cache, a_base } = prepare("merge");
    let journal_dir = tempfile::tempdir().unwrap();
    let journal = SyncJournal::open(&journal_dir.path().join("journal")).unwrap();

    // Steam commits x on A; the journal records the commit and its snapshot.
    let commit_id = "a-1";
    journal
        .enqueue_stats_commit(&StatsCommit {
            owner_scope: a.scope.clone(),
            owner_steam_id64: a.steam_id64.clone(),
            commit_id: commit_id.into(),
            app_id: APP_ID,
            base_crc_stats: a_base,
            dirty_stat_ids: vec![STAT_X],
            observed_at: now(),
        })
        .unwrap();
    assert!(journal
        .complete_stats_snapshot(&a.snapshot(commit_id, a_base, &[STAT_X], &a_cache))
        .unwrap());
    let queued = journal
        .pending_stats_snapshots(&a.scope, &a.steam_id64, now())
        .unwrap();
    assert_eq!(queued.len(), 1);

    // The server refuses the stale baseline.
    let refused = a.upload(&queued[0].value);
    println!("scenario 6: upload with stale base {a_base:?} -> {refused:?}");
    assert_eq!(refused.status, AppStatsUploadStatus::StatsOutOfDate);
    assert!(journal
        .reopen_stats_commit(&queued[0], refused.crc_stats, now())
        .unwrap());
    let merge = journal
        .pending_stats_merge(&a.scope, &a.steam_id64, APP_ID)
        .unwrap()
        .expect("refused values wait for a merge");
    assert_eq!(merge.dirty_stat_ids, vec![STAT_X]);
    // While the merge is pending, a snapshot from the stale cache is refused
    // by the journal itself.
    assert!(!journal
        .complete_stats_snapshot(&a.snapshot(commit_id, a_base, &[STAT_X], &a_cache))
        .unwrap());

    // The stats proxy fetches the full authoritative state without a client
    // baseline and merges the refused values into it.
    let authority = a.pull(None);
    let base = match &authority {
        AppStatsResult::Modified { crc_stats, .. } => *crc_stats,
        other => panic!("full state expected: {other:?}"),
    };
    println!("scenario 6: authority={authority:?}");
    let merged = crate::stats_merge::merge_refused_stats(
        authority,
        &schema(),
        &merge.dirty_stat_ids,
        &merge.achievements,
        &merge.stats,
    )
    .expect("merge succeeds");
    assert!(journal
        .settle_stats_merge(&a.scope, &a.steam_id64, APP_ID, commit_id, base)
        .unwrap());

    // Steam applies the merged response to its cache and the commit is rebuilt
    // from it on the backend's baseline.
    let merged_cache = LocalCache::from_result(&merged);
    println!("scenario 6: merged cache={merged_cache:?}");
    assert!(journal
        .complete_stats_snapshot(&a.snapshot(commit_id, None, &[STAT_X], &merged_cache))
        .unwrap());
    let queued = journal
        .pending_stats_snapshots(&a.scope, &a.steam_id64, now())
        .unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].value.base_crc_stats, base);
    let resubmitted = a.upload(&queued[0].value);
    println!("scenario 6: resubmit with base {base:?} -> {resubmitted:?}");
    assert!(matches!(
        resubmitted.status,
        AppStatsUploadStatus::Applied | AppStatsUploadStatus::NoChange
    ));
    journal.acknowledge(&queued[0]).unwrap();

    let state = final_state(&a);
    println!("scenario 6: final server state={state:?}");
    assert_eq!(state.x, "10", "A's refused x survives");
    assert_eq!(state.y, "5", "B's y survives");
    assert_eq!(
        state.unlocked_at,
        Some(1_800_000_000),
        "B's unlock survives"
    );
}

/// Resubmitting the stale cache on the crc the refusal returned is what the
/// client did before the merge flow. The server accepts it as a full
/// replacement, so B's values are lost. This shows the scenario above detects
/// the lost update.
#[test]
#[ignore = "needs a running Cumulus server; see scripts/cumulus-sim.sh"]
fn cumulus_sim_6_stale_resubmission_loses_the_other_devices_values() {
    let Refusal { a, a_cache, a_base } = prepare("stale");
    let refused = a.upload(&a.snapshot("a-1", a_base, &[STAT_X], &a_cache));
    assert_eq!(refused.status, AppStatsUploadStatus::StatsOutOfDate);
    let resubmitted = a.upload(&a.snapshot("a-1", refused.crc_stats, &[STAT_X], &a_cache));
    let state = final_state(&a);
    println!("scenario 6 (old behavior): refused={refused:?} resubmitted={resubmitted:?} final={state:?}");
    assert_eq!(state.x, "10");
    assert_eq!(state.y, "1", "B's y was overwritten by the stale cache");
    assert_eq!(state.unlocked_at, None, "B's unlock was reverted");
}
