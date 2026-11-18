//! Device stats simulation against a running Cumulus server: schema naming,
//! credential error classification and the stats wakeup stream.
//!
//! Ignored by default; `scripts/cumulus-sim.sh` starts a throwaway server and
//! runs them with `CUMULUS_SIM_URL`, `CUMULUS_SIM_ADMIN_USER` and
//! `CUMULUS_SIM_ADMIN_PASSWORD` set.

mod cumulus_sim {
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use vapor_forge_cloud_core::{
        AccountStatsWakeup, AccountStreamEvent, AchievementSchema, AppStatsQuery, AppStatsResult,
        AppStatsUploadStatus, CloudBackend, DeviceDescriptor, OfficialAchievementState,
        OfficialStatState, SteamAppSnapshot, StreamCancellation, UploadIdentity,
    };
    use vapor_forge_cloud_cumulus::{
        achievement, ensure_device_bound, principal_scope, CumulusBackend, CumulusError,
        CumulusSettings,
    };

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

    fn agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .build()
            .new_agent()
    }

    fn read_json(mut response: ureq::http::Response<ureq::Body>, what: &str) -> Value {
        let status = response.status().as_u16();
        let body = response.body_mut().read_to_string().unwrap_or_default();
        assert!(
            (200..300).contains(&status),
            "{what} failed with HTTP {status}: {body}"
        );
        serde_json::from_str(&body).unwrap_or(Value::Null)
    }

    fn session_cookie(response: &ureq::http::Response<ureq::Body>) -> String {
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("cml_session="))
            .and_then(|value| value.split(';').next())
            .expect("login sets a session cookie")
            .to_string()
    }

    /// A browser session, either the administrator or a member.
    struct Session {
        url: String,
        cookie: String,
    }

    const MEMBER_PASSWORD: &str = "SimPassphrase!2026-member";

    impl Session {
        fn login(path: &str, body: Value) -> Self {
            let url = env("CUMULUS_SIM_URL");
            let response = agent()
                .post(&format!("{url}{path}"))
                .header("Content-Type", "application/json")
                .send(serde_json::to_vec(&body).unwrap().as_slice())
                .unwrap();
            let cookie = session_cookie(&response);
            read_json(response, path);
            Self { url, cookie }
        }

        fn admin() -> Self {
            Self::login(
                "/admin/api/login",
                json!({
                    "username": env("CUMULUS_SIM_ADMIN_USER"),
                    "password": env("CUMULUS_SIM_ADMIN_PASSWORD"),
                }),
            )
        }

        fn member(email: &str) -> Self {
            Self::login(
                "/api/v1/auth/login",
                json!({ "email": email, "password": MEMBER_PASSWORD }),
            )
        }

        fn post(&self, path: &str, body: Value) -> Value {
            let response = agent()
                .post(&format!("{}{path}", self.url))
                .header("Cookie", &self.cookie)
                .header("Content-Type", "application/json")
                .send(serde_json::to_vec(&body).unwrap().as_slice())
                .unwrap();
            read_json(response, path)
        }

        fn delete(&self, path: &str) {
            let response = agent()
                .delete(&format!("{}{path}", self.url))
                .header("Cookie", &self.cookie)
                .call()
                .unwrap();
            read_json(response, path);
        }

        /// Create an isolated user; returns its id and email.
        fn create_user(&self, label: &str) -> (i64, String) {
            let name = format!("sim-{label}-{}", unique());
            let email = format!("{name}@example.test");
            let id = self.post(
                "/admin/api/users",
                json!({ "name": name, "email": email, "password": MEMBER_PASSWORD }),
            )["id"]
                .as_i64()
                .unwrap();
            (id, email)
        }

        /// Create an unbound device key; returns its id and plaintext.
        fn create_token(&self, user_id: i64) -> (i64, String) {
            let created = self.post(
                &format!("/admin/api/users/{user_id}/tokens"),
                json!({ "label": "simulation" }),
            );
            (
                created["id"].as_i64().unwrap(),
                created["token"].as_str().unwrap().to_string(),
            )
        }
    }

    fn settings(token: &str) -> CumulusSettings {
        CumulusSettings {
            server_url: env("CUMULUS_SIM_URL"),
            token: token.to_string(),
            timeout_connect_ms: 5_000,
            timeout_ms: 20_000,
        }
    }

    fn descriptor(client_id: u64) -> DeviceDescriptor {
        DeviceDescriptor {
            client_id,
            machine_name: format!("sim-{client_id}"),
            os_type: None,
            device_type: None,
        }
    }

    /// One simulated Steam device bound to its own key.
    struct Device {
        settings: CumulusSettings,
        client_id: u64,
        steam_id64: String,
    }

    impl Device {
        fn bound(token: String, steam_id64: &str) -> Self {
            let client_id = unique();
            let settings = settings(&token);
            ensure_device_bound(&settings, &descriptor(client_id)).expect("device binds");
            Self {
                settings,
                client_id,
                steam_id64: steam_id64.to_string(),
            }
        }

        fn backend(&self) -> CumulusBackend {
            CumulusBackend::new(self.settings.clone())
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

        fn upload_schema(&self, app_id: u32, version: Option<String>, content: &[u8]) {
            let outcome = achievement::upload_schema(
                &self.settings,
                self.client_id,
                &AchievementSchema {
                    owner_scope: String::new(),
                    app_id,
                    language: "english".into(),
                    schema_version: version,
                    content: content.to_vec(),
                },
            )
            .expect("schema upload");
            assert_eq!(outcome, achievement::SchemaUploadOutcome::Uploaded);
        }

        fn upload_stats(
            &self,
            app_id: u32,
            base_crc_stats: Option<u32>,
            dirty_stat_ids: &[u32],
            stats: &[(&str, &str)],
        ) -> vapor_forge_cloud_core::AppStatsUploadResult {
            let result = achievement::upload_snapshot(
                &self.settings,
                &self.identity(),
                &SteamAppSnapshot {
                    owner_scope: String::new(),
                    owner_steam_id64: self.steam_id64.clone(),
                    commit_id: format!("commit-{}", unique()),
                    app_id,
                    base_crc_stats,
                    dirty_stat_ids: dirty_stat_ids.to_vec(),
                    achievements: vec![OfficialAchievementState {
                        key: "ACH_WIN".into(),
                        unlocked: false,
                        unlocked_at: None,
                    }],
                    stats: stats
                        .iter()
                        .map(|(key, value)| OfficialStatState {
                            key: key.to_string(),
                            value_type: "int".into(),
                            value: value.to_string(),
                        })
                        .collect(),
                    observed_at: now(),
                },
            )
            .expect("stats upload");
            result
                .stats_apps
                .into_iter()
                .find(|app| app.app_id == app_id)
                .expect("upload result names the app")
        }

        fn pull(&self, app_id: u32, schema_version: &str) -> AppStatsResult {
            achievement::pull_app_stats(
                &self.settings,
                self.client_id,
                &self.steam_id64,
                &AppStatsQuery {
                    app_id,
                    client_crc_stats: None,
                    schema_version: schema_version.to_string(),
                },
            )
            .expect("user-stats read")
        }
    }

    fn steam_id64() -> String {
        (76_561_197_960_265_728 + unique() % 1_000_000_000).to_string()
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

    /// Binary KeyValues stats schema: one achievement block (stat 1) and two
    /// integer stats (2 and 3).
    fn schema(app_id: u32) -> Vec<u8> {
        let mut schema = Vec::new();
        kv_object(&mut schema, &app_id.to_string(), |root| {
            kv_object(root, "stats", |stats| {
                kv_object(stats, "1", |stat| {
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
                kv_object(stats, "2", |stat| {
                    kv_string(stat, "name", "STAT_X");
                    kv_int(stat, "type", 1);
                });
                kv_object(stats, "3", |stat| {
                    kv_string(stat, "name", "STAT_Y");
                    kv_int(stat, "type", 1);
                });
            });
        });
        schema
    }

    /// The name the client gives a schema Valve supplied no version for.
    fn content_version(content: &[u8]) -> String {
        format!("{:x}", Sha256::digest(content))
    }

    fn stat_value(result: &AppStatsResult, key: &str) -> Option<String> {
        match result {
            AppStatsResult::Modified { stats, .. } => stats
                .iter()
                .find(|stat| stat.stat_key == key)
                .map(|stat| stat.value.clone()),
            _ => None,
        }
    }

    #[test]
    #[ignore = "needs a running Cumulus server; see scripts/cumulus-sim.sh"]
    fn schema_named_by_content_hash_matches_user_stats_queries() {
        let admin = Session::admin();
        let (user_id, _) = admin.create_user("schema");
        let steam_id64 = steam_id64();
        let device = Device::bound(admin.create_token(user_id).1, &steam_id64);

        // The client names a versionless schema by the SHA-256 of its bytes and
        // uploads it under that name.
        let named_app = 620;
        let named = schema(named_app);
        let named_version = content_version(&named);
        device.upload_schema(named_app, Some(named_version.clone()), &named);
        let first = device.upload_stats(named_app, None, &[2], &[("STAT_X", "1"), ("STAT_Y", "2")]);
        assert_eq!(first.status, AppStatsUploadStatus::Uninitialized);
        let result = device.pull(named_app, &named_version);
        println!("scenario 7a: version={named_version} result={result:?}");
        assert!(
            matches!(result, AppStatsResult::Modified { ref schema_version, crc_stats: Some(_), .. } if *schema_version == named_version),
            "{result:?}"
        );
        assert_eq!(stat_value(&result, "STAT_X").as_deref(), Some("1"));

        // A schema stored without any version is found by its content name.
        let legacy_app = 621;
        let legacy = schema(legacy_app);
        device.upload_schema(legacy_app, None, &legacy);
        device.upload_stats(legacy_app, None, &[2], &[("STAT_X", "5"), ("STAT_Y", "6")]);
        let result = device.pull(legacy_app, &content_version(&legacy));
        println!("scenario 7b: result={result:?}");
        assert!(
            matches!(result, AppStatsResult::Modified { .. }),
            "{result:?}"
        );
        assert_eq!(stat_value(&result, "STAT_Y").as_deref(), Some("6"));

        // Control: any other name is a mismatch, so the matches above are real.
        let result = device.pull(legacy_app, &"0".repeat(64));
        println!("scenario 7c: wrong version -> {result:?}");
        assert!(
            matches!(result, AppStatsResult::SchemaMismatch { .. }),
            "{result:?}"
        );
    }

    fn assert_blocked(error: &CumulusError, code: &str) {
        println!(
            "scenario 8: {code}: status={:?} code={:?} retryable={} blocked={}",
            error.status(),
            error.code(),
            error.is_retryable(),
            error.is_credential_blocked()
        );
        assert_eq!(error.code(), Some(code), "{error}");
        assert!(error.is_credential_blocked(), "{error}");
        assert!(!error.is_retryable(), "{error}");
    }

    fn assert_retryable(error: &CumulusError, code: &str) {
        println!(
            "scenario 8: {code}: status={:?} code={:?} retryable={} blocked={}",
            error.status(),
            error.code(),
            error.is_retryable(),
            error.is_credential_blocked()
        );
        assert_eq!(error.code(), Some(code), "{error}");
        assert!(!error.is_credential_blocked(), "{error}");
        assert!(error.is_retryable(), "{error}");
    }

    #[test]
    #[ignore = "needs a running Cumulus server; see scripts/cumulus-sim.sh"]
    fn server_credential_refusals_are_classified() {
        let admin = Session::admin();
        let (user_id, email) = admin.create_user("errors");
        let steam_id64 = steam_id64();

        // A key bound to one device cannot be bound to another.
        let (token_id, token) = admin.create_token(user_id);
        let device = Device::bound(token.clone(), &steam_id64);
        let error =
            ensure_device_bound(&settings(&token), &descriptor(device.client_id + 1)).unwrap_err();
        assert_blocked(&error, "credential_bound");
        let mapped = CumulusBackend::new(settings(&token))
            .ensure_device_bound(&descriptor(device.client_id + 2))
            .unwrap_err();
        assert!(mapped.is_credential_blocked() && !mapped.is_retryable());

        // A replacement key waiting for its device refuses other devices, and
        // waits for the right one when no device is named.
        let member = Session::member(&email);
        let rotation = member.post(
            &format!("/api/v1/member/devices/{}/key-rotation", device.client_id),
            json!({ "label": "rotation" }),
        );
        let rotated = rotation["token"]
            .as_str()
            .unwrap_or_else(|| panic!("rotation returns a key: {rotation}"))
            .to_string();
        let error = principal_scope(&settings(&rotated), Some(device.client_id + 1)).unwrap_err();
        assert_blocked(&error, "steam_client_id_mismatch");
        let error = principal_scope(&settings(&rotated), None).unwrap_err();
        assert_retryable(&error, "steam_client_id_required");

        // An unbound key on a device API asks for device identity first.
        let (_, unbound) = admin.create_token(user_id);
        let error = achievement::pull_app_stats(
            &settings(&unbound),
            unique(),
            &steam_id64,
            &AppStatsQuery {
                app_id: 620,
                client_crc_stats: None,
                schema_version: "0".repeat(64),
            },
        )
        .unwrap_err();
        assert_retryable(&error, "device_identity_required");

        // A revoked key is refused for good.
        admin.delete(&format!("/admin/api/tokens/{token_id}"));
        let error = principal_scope(&settings(&token), Some(device.client_id)).unwrap_err();
        assert_blocked(&error, "token_revoked");
    }

    /// Mirror of the hooks account downlink check, which is compiled only on
    /// Linux: a wakeup this device caused carries nothing new for it.
    fn wakeup_from_this_device(wakeup: &AccountStatsWakeup, client_id: u64) -> bool {
        wakeup
            .origin_client_id
            .as_deref()
            .and_then(|value| value.parse::<u64>().ok())
            == Some(client_id)
    }

    struct Subscription {
        cancellation: StreamCancellation,
        events: mpsc::Receiver<AccountStreamEvent>,
        join: std::thread::JoinHandle<()>,
    }

    fn subscribe(device: &Device) -> Subscription {
        let cancellation = StreamCancellation::new();
        let (sender, events) = mpsc::channel();
        let backend = device.backend();
        let client_id = device.client_id;
        let steam_id64 = device.steam_id64.clone();
        let stream_cancellation = cancellation.clone();
        let join = std::thread::spawn(move || {
            let mut on_event = |event| {
                let _ = sender.send(event);
            };
            backend
                .stream_account_events(client_id, &steam_id64, &stream_cancellation, &mut on_event)
                .expect("account stream");
        });
        Subscription {
            cancellation,
            events,
            join,
        }
    }

    impl Subscription {
        fn wait_for(
            &self,
            what: &str,
            mut matches: impl FnMut(&AccountStreamEvent) -> bool,
        ) -> AccountStreamEvent {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                match self.events.recv_timeout(remaining) {
                    Ok(event) if matches(&event) => return event,
                    Ok(_) => {}
                    Err(_) => panic!("timed out waiting for {what}"),
                }
            }
        }

        fn stop(self) {
            self.cancellation.cancel();
            self.join.join().unwrap();
        }
    }

    #[test]
    #[ignore = "needs a running Cumulus server; see scripts/cumulus-sim.sh"]
    fn stats_wakeup_names_the_uploading_device() {
        let admin = Session::admin();
        let (user_id, _) = admin.create_user("wakeup");
        let steam_id64 = steam_id64();
        let a = Device::bound(admin.create_token(user_id).1, &steam_id64);
        let b = Device::bound(admin.create_token(user_id).1, &steam_id64);
        let app_id = 622;
        let content = schema(app_id);
        a.upload_schema(app_id, Some(content_version(&content)), &content);
        let initial = a.upload_stats(app_id, None, &[2], &[("STAT_X", "1"), ("STAT_Y", "1")]);
        let base = initial.crc_stats;

        let stream_a = subscribe(&a);
        let stream_b = subscribe(&b);
        for stream in [&stream_a, &stream_b] {
            stream.wait_for("baseline", |event| {
                matches!(event, AccountStreamEvent::Baseline(_))
            });
        }
        // Both streams are subscribed once their baseline arrived; the opening
        // wakeup that follows it has no origin.
        std::thread::sleep(Duration::from_millis(300));

        let applied = a.upload_stats(app_id, base, &[2], &[("STAT_X", "2"), ("STAT_Y", "1")]);
        assert_eq!(applied.status, AppStatsUploadStatus::Applied);

        let from_a = |event: &AccountStreamEvent| {
            matches!(event, AccountStreamEvent::StatsWakeup(wakeup)
                if wakeup.origin_client_id.is_some())
        };
        let seen_by_a = stream_a.wait_for("wakeup on A", from_a);
        let seen_by_b = stream_b.wait_for("wakeup on B", from_a);
        stream_a.stop();
        stream_b.stop();

        let (
            AccountStreamEvent::StatsWakeup(seen_by_a),
            AccountStreamEvent::StatsWakeup(seen_by_b),
        ) = (seen_by_a, seen_by_b)
        else {
            unreachable!()
        };
        println!(
            "scenario 9: a={} b={} wakeup on A={seen_by_a:?} wakeup on B={seen_by_b:?}",
            a.client_id, b.client_id
        );
        let expected_origin = a.client_id.to_string();
        assert_eq!(
            seen_by_a.origin_client_id.as_deref(),
            Some(expected_origin.as_str())
        );
        assert_eq!(
            seen_by_b.origin_client_id.as_deref(),
            Some(expected_origin.as_str())
        );
        assert_eq!(seen_by_b.app_ids, vec![app_id]);
        assert_eq!(seen_by_b.steam_id64, steam_id64);
        assert!(
            wakeup_from_this_device(&seen_by_a, a.client_id),
            "A skips its own wakeup"
        );
        assert!(
            !wakeup_from_this_device(&seen_by_b, b.client_id),
            "B acts on A's wakeup"
        );
    }
}
