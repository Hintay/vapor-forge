use super::*;
use rusqlite::params;

fn event(id: &str) -> QueuedAchievementEvent {
    QueuedAchievementEvent {
        owner_scope: "scope-a".into(),
        owner_steam_id64: "76561198000000091".into(),
        event_id: id.into(),
        app_id: 620,
        achievement_key: "WAKE_UP".into(),
        kind: "unlock".into(),
        progress_current: None,
        progress_max: None,
        observed_at: 1_800_000_002,
        unlocked_at: Some(1_800_000_000),
    }
}

fn schema() -> QueuedAchievementSchema {
    QueuedAchievementSchema {
        owner_scope: "scope-a".into(),
        app_id: 620,
        language: "english".into(),
        schema_version: Some("abc123".into()),
        content: b"binary-schema".to_vec(),
    }
}

#[test]
fn persists_deduplicates_and_delivers_events() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("outbox.db");
    let first = event("11111111-1111-4111-8111-111111111111");
    {
        let mut outbox = Outbox::open(&path).unwrap();
        assert!(outbox.enqueue(&first, 10).unwrap());
        assert!(!outbox.enqueue(&first, 11).unwrap());
        assert_eq!(outbox.len().unwrap(), 1);
        outbox
            .mark_failed(std::slice::from_ref(&first), 20)
            .unwrap();
        assert!(outbox
            .pending(20, &first.owner_scope, &first.owner_steam_id64)
            .unwrap()
            .is_empty());
    }
    let mut reopened = Outbox::open(&path).unwrap();
    assert_eq!(
        reopened
            .pending(21, &first.owner_scope, &first.owner_steam_id64)
            .unwrap(),
        vec![first.clone()]
    );
    reopened.mark_delivered(&[first]).unwrap();
    assert_eq!(reopened.len().unwrap(), 0);
}

#[test]
fn pending_events_are_delivered_in_observation_order() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("outbox.db");
    let outbox = Outbox::open(&path).unwrap();
    let mut clear = event("22222222-2222-4222-8222-222222222222");
    clear.kind = "clear".into();
    clear.observed_at = 20;
    clear.unlocked_at = None;
    let mut stale_unlock = event("11111111-1111-4111-8111-111111111111");
    stale_unlock.observed_at = 10;

    outbox.enqueue(&clear, 10).unwrap();
    outbox.enqueue(&stale_unlock, 20).unwrap();

    assert_eq!(
        outbox
            .pending(20, &clear.owner_scope, &clear.owner_steam_id64)
            .unwrap(),
        vec![stale_unlock, clear]
    );
}

#[test]
fn persists_device_identity_across_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("outbox.db");
    let descriptor = DeviceDescriptor {
        client_id: u64::MAX - 7,
        machine_name: "Steam Deck".into(),
        os_type: Some(20),
        device_type: Some(1),
    };
    {
        let outbox = Outbox::open(&path).unwrap();
        outbox.store_device_descriptor(&descriptor, 10).unwrap();
    }

    let reopened = Outbox::open(&path).unwrap();
    assert_eq!(reopened.load_device_descriptor().unwrap(), Some(descriptor));
}

#[test]
fn durable_pending_events_are_claimed_only_by_the_same_steam_account() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("outbox.db");
    let mut first = event("11111111-1111-4111-8111-111111111111");
    first.owner_scope.clear();
    let mut other = event("22222222-2222-4222-8222-222222222222");
    other.owner_scope.clear();
    other.owner_steam_id64 = "76561198000000092".into();
    let mut pending_schema = schema();
    pending_schema.owner_scope.clear();
    {
        let outbox = Outbox::open(&path).unwrap();
        outbox.enqueue(&first, 10).unwrap();
        outbox.enqueue(&other, 11).unwrap();
        outbox.enqueue_schema(&pending_schema, 12).unwrap();
    }

    let reopened = Outbox::open(&path).unwrap();
    reopened
        .attribute_pending("scope-a", &first.owner_steam_id64)
        .unwrap();
    reopened.attribute_pending_schemas("scope-a").unwrap();
    let mut attributed = first.clone();
    attributed.owner_scope = "scope-a".into();
    assert_eq!(
        reopened
            .pending(12, "scope-a", &first.owner_steam_id64)
            .unwrap(),
        vec![attributed]
    );
    assert_eq!(
        reopened.pending(12, "", &other.owner_steam_id64).unwrap(),
        vec![other]
    );
    let mut attributed_schema = pending_schema;
    attributed_schema.owner_scope = "scope-a".into();
    assert_eq!(
        reopened.pending_schemas(12, "scope-a").unwrap(),
        vec![attributed_schema]
    );
}

#[test]
fn attributing_pending_progress_keeps_the_newest_value() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("outbox.db");
    let outbox = Outbox::open(&path).unwrap();
    let mut current = event("11111111-1111-4111-8111-111111111111");
    current.kind = "progress".into();
    current.progress_current = Some(2);
    current.progress_max = Some(10);
    outbox.enqueue(&current, 10).unwrap();

    let mut pending = current.clone();
    pending.owner_scope.clear();
    pending.event_id = "22222222-2222-4222-8222-222222222222".into();
    pending.progress_current = Some(8);
    outbox.enqueue(&pending, 11).unwrap();
    outbox
        .attribute_pending("scope-a", &current.owner_steam_id64)
        .unwrap();

    pending.owner_scope = "scope-a".into();
    assert_eq!(
        outbox
            .pending(11, "scope-a", &current.owner_steam_id64)
            .unwrap(),
        vec![pending]
    );
}

#[test]
fn event_id_collision_does_not_discard_previous_progress() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("outbox.db");
    let outbox = Outbox::open(&path).unwrap();

    let mut previous = event("11111111-1111-4111-8111-111111111111");
    previous.kind = "progress".into();
    previous.progress_current = Some(3);
    previous.progress_max = Some(10);
    outbox.enqueue(&previous, 10).unwrap();

    let mut collision = event("22222222-2222-4222-8222-222222222222");
    collision.achievement_key = "OTHER_KEY".into();
    outbox.enqueue(&collision, 11).unwrap();

    let mut replacement = previous.clone();
    replacement.event_id.clone_from(&collision.event_id);
    replacement.progress_current = Some(7);
    assert!(!outbox.enqueue(&replacement, 12).unwrap());

    assert_eq!(
        outbox
            .pending(12, &previous.owner_scope, &previous.owner_steam_id64)
            .unwrap(),
        vec![previous, collision]
    );
}

#[test]
fn event_acknowledgements_cannot_cross_owner_scope() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("outbox.db");
    let mut outbox = Outbox::open(&path).unwrap();
    let original = event("11111111-1111-4111-8111-111111111111");
    outbox.enqueue(&original, 10).unwrap();
    let mut forged = original.clone();
    forged.owner_scope = "scope-b".into();
    forged.owner_steam_id64 = "76561198000000092".into();

    outbox
        .mark_delivered(std::slice::from_ref(&forged))
        .unwrap();
    outbox
        .mark_failed(std::slice::from_ref(&forged), 10)
        .unwrap();
    outbox.mark_rejected(&[forged], "wrong owner", 10).unwrap();

    assert_eq!(
        outbox
            .pending(10, &original.owner_scope, &original.owner_steam_id64)
            .unwrap(),
        vec![original]
    );
}

#[test]
fn progress_retention_is_scoped_to_one_owner() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("outbox.db");
    let mut outbox = Outbox::open(&path).unwrap();
    let mut other = event("ffffffff-ffff-4fff-8fff-ffffffffffff");
    other.owner_scope = "scope-b".into();
    other.kind = "progress".into();
    other.progress_current = Some(1);
    other.progress_max = Some(10);
    outbox.enqueue(&other, 1).unwrap();

    let transaction = outbox.connection.transaction().unwrap();
    for index in 0..5_001 {
        transaction
            .execute(
                "INSERT INTO achievement_outbox (
                    event_id, owner_scope, owner_steam_id64, app_id, achievement_key,
                    kind, progress_current, progress_max, observed_at, created_at
                 ) VALUES (?1, 'scope-a', '76561198000000091', ?2, ?3,
                           'progress', 1, 10, 1, ?4)",
                params![
                    format!("bulk-{index}"),
                    10_000_i64 + i64::from(index),
                    format!("KEY_{index}"),
                    index
                ],
            )
            .unwrap();
    }
    transaction.commit().unwrap();
    let mut trigger = event("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
    trigger.kind = "progress".into();
    trigger.progress_current = Some(1);
    trigger.progress_max = Some(10);
    trigger.app_id = 999;
    trigger.achievement_key = "TRIGGER".into();
    outbox.enqueue(&trigger, 6_000).unwrap();

    assert_eq!(
        outbox
            .pending(6_000, &other.owner_scope, &other.owner_steam_id64)
            .unwrap(),
        vec![other]
    );
    let retained: i64 = outbox
        .connection
        .query_row(
            "SELECT COUNT(*) FROM achievement_outbox WHERE owner_scope = 'scope-a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained, 5_000);
}

#[test]
fn persists_and_coalesces_latest_schema() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("outbox.db");
    let mut latest = schema();
    {
        let outbox = Outbox::open(&path).unwrap();
        outbox.enqueue_schema(&latest, 10).unwrap();
        latest.schema_version = Some("def456".into());
        latest.content = b"new-schema".to_vec();
        outbox.enqueue_schema(&latest, 11).unwrap();
    }
    let outbox = Outbox::open(&path).unwrap();
    assert_eq!(
        outbox.pending_schemas(11, "scope-a").unwrap(),
        vec![latest.clone()]
    );
    outbox.mark_schema_delivered(&latest).unwrap();
    assert!(outbox.pending_schemas(11, "scope-a").unwrap().is_empty());
}

#[test]
fn isolates_accounts_and_coalesces_progress() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("outbox.db");
    let outbox = Outbox::open(&path).unwrap();
    let mut first = event("11111111-1111-4111-8111-111111111111");
    first.kind = "progress".into();
    first.progress_current = Some(1);
    first.progress_max = Some(10);
    let mut latest = first.clone();
    latest.event_id = "22222222-2222-4222-8222-222222222222".into();
    latest.progress_current = Some(7);
    let mut other_account = event("33333333-3333-4333-8333-333333333333");
    other_account.owner_scope = "scope-b".into();
    let mut other_steam_account = event("44444444-4444-4444-8444-444444444444");
    other_steam_account.owner_steam_id64 = "76561198000000092".into();

    outbox.enqueue(&first, 10).unwrap();
    outbox.enqueue(&latest, 11).unwrap();
    outbox.enqueue(&other_account, 12).unwrap();
    outbox.enqueue(&other_steam_account, 12).unwrap();

    assert_eq!(
        outbox.pending(12, "scope-a", "76561198000000091").unwrap(),
        vec![latest]
    );
    assert_eq!(
        outbox.pending(12, "scope-b", "76561198000000091").unwrap(),
        vec![other_account]
    );
    assert_eq!(
        outbox.pending(12, "scope-a", "76561198000000092").unwrap(),
        vec![other_steam_account]
    );
}

#[test]
fn persists_conflict_choices_across_reopen_and_failure() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("outbox.db");
    let local = QueuedConflictResolution {
        owner_scope: "credential-a".into(),
        event_id: "conflict-local-1".into(),
        app_id: 480,
        base_change_number: 1,
        remote_change_number: 2,
        resolution: "kept_local".into(),
        machine_name: Some("Deck".into()),
    };
    {
        let mut outbox = Outbox::open(&path).unwrap();
        outbox.enqueue_conflict(&local, 10).unwrap();
        assert_eq!(
            outbox
                .pending_local_conflict("credential-a", 480, 2)
                .unwrap(),
            Some(local.clone())
        );
    }

    let mut reopened = Outbox::open(&path).unwrap();
    assert_eq!(
        reopened
            .pending_local_conflict("credential-a", 480, 2)
            .unwrap(),
        Some(local)
    );
    let cloud = QueuedConflictResolution {
        owner_scope: "credential-a".into(),
        event_id: "conflict-cloud-1".into(),
        app_id: 480,
        base_change_number: 2,
        remote_change_number: 3,
        resolution: "kept_cloud".into(),
        machine_name: Some("Deck".into()),
    };
    reopened.enqueue_conflict(&cloud, 20).unwrap();
    assert!(reopened
        .pending_local_conflict("credential-a", 480, 2)
        .unwrap()
        .is_none());
    assert_eq!(
        reopened
            .pending_cloud_conflicts(20, "credential-a")
            .unwrap(),
        vec![cloud.clone()]
    );
    reopened.mark_conflict_failed(&cloud, 20).unwrap();
    assert!(reopened
        .pending_cloud_conflicts(20, "credential-a")
        .unwrap()
        .is_empty());
    assert_eq!(
        reopened
            .pending_cloud_conflicts(21, "credential-a")
            .unwrap(),
        vec![cloud.clone()]
    );
    reopened.mark_conflict_delivered(&cloud).unwrap();
    assert_eq!(reopened.conflict_len().unwrap(), 0);
}

#[test]
fn conflict_outbox_operations_are_credential_scoped() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("outbox.db");
    let mut outbox = Outbox::open(&path).unwrap();
    let first = QueuedConflictResolution {
        owner_scope: "credential-a".into(),
        event_id: "conflict-a".into(),
        app_id: 480,
        base_change_number: 1,
        remote_change_number: 2,
        resolution: "kept_cloud".into(),
        machine_name: None,
    };
    let second = QueuedConflictResolution {
        owner_scope: "credential-b".into(),
        event_id: "conflict-b".into(),
        ..first.clone()
    };
    outbox.enqueue_conflict(&first, 10).unwrap();
    outbox.enqueue_conflict(&second, 10).unwrap();

    assert_eq!(
        outbox.pending_cloud_conflicts(10, "credential-a").unwrap(),
        vec![first.clone()]
    );
    assert_eq!(
        outbox.pending_cloud_conflicts(10, "credential-b").unwrap(),
        vec![second.clone()]
    );
    outbox.mark_conflict_failed(&first, 10).unwrap();
    assert_eq!(
        outbox.pending_cloud_conflicts(10, "credential-b").unwrap(),
        vec![second.clone()]
    );
    outbox.mark_conflict_delivered(&first).unwrap();
    assert_eq!(outbox.conflict_len().unwrap(), 1);
    assert_eq!(
        outbox.pending_cloud_conflicts(10, "credential-b").unwrap(),
        vec![second]
    );
}

#[test]
fn endpoint_scope_survives_key_rotation_and_normalizes_server_url() {
    let first_url = " https://cloud.example.test/api/ ";
    let normalized_url = "https://cloud.example.test/api";
    assert_eq!(endpoint_scope(first_url), endpoint_scope(normalized_url));
    assert_ne!(
        credential_scope(first_url, "old-token"),
        credential_scope(normalized_url, "new-token")
    );
    assert_eq!(
        credential_scope(first_url, "old-token"),
        credential_scope(normalized_url, "old-token")
    );
    assert_ne!(
        endpoint_scope(first_url),
        endpoint_scope("https://other.example.test/api")
    );
}
