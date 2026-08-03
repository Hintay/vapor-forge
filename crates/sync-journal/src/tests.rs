use super::*;
use vapor_forge_cloud_core::{
    AchievementSchema, DeviceDescriptor, OfficialAchievementState, OfficialStatState,
    PlaytimeEntry, PlaytimeSession, StatsCommit, SteamAppSnapshot,
};

const SCOPE: &str = "scope-a";
const STEAM_ID: &str = "76561198000000001";

fn journal(directory: &tempfile::TempDir) -> SyncJournal {
    SyncJournal::open(&directory.path().join("sync-journal.stry")).unwrap()
}

fn playtime(observed_at: i64, minutes: u32) -> PlaytimeEntry {
    PlaytimeEntry {
        owner_scope: SCOPE.into(),
        owner_steam_id64: STEAM_ID.into(),
        app_id: 620,
        playtime_minutes: minutes,
        playtime_2weeks_minutes: 20,
        last_played_at: Some(1_800_000_000),
        observed_at,
    }
}

fn playtime_session(id: &str) -> PlaytimeSession {
    PlaytimeSession {
        owner_scope: SCOPE.into(),
        owner_steam_id64: STEAM_ID.into(),
        session_id: id.into(),
        app_id: 620,
        started_at: 1_800_000_000,
        seconds: 125,
        offline: false,
        owner_account_id: 39734273,
        observed_at: 1_800_000_125,
    }
}

fn stats_commit(commit_id: &str, observed_at: i64) -> StatsCommit {
    StatsCommit {
        owner_scope: SCOPE.into(),
        owner_steam_id64: STEAM_ID.into(),
        commit_id: commit_id.into(),
        app_id: 620,
        base_crc_stats: Some(0x1234_5678),
        dirty_stat_ids: vec![11, 12],
        observed_at,
    }
}

fn steam_snapshot(commit_id: &str, observed_at: i64) -> SteamAppSnapshot {
    SteamAppSnapshot {
        owner_scope: SCOPE.into(),
        owner_steam_id64: STEAM_ID.into(),
        commit_id: commit_id.into(),
        app_id: 620,
        base_crc_stats: Some(0x1234_5678),
        dirty_stat_ids: vec![11, 12],
        achievements: vec![OfficialAchievementState {
            key: "ACH_WIN".into(),
            unlocked: true,
            unlocked_at: Some(1_800_000_000),
        }],
        stats: vec![OfficialStatState {
            key: "STAT_SCORE".into(),
            value_type: "int".into(),
            value: "42".into(),
        }],
        observed_at,
    }
}

fn conflict(event_id: &str, resolution: &str) -> ConflictResolutionEvent {
    ConflictResolutionEvent {
        owner_scope: SCOPE.into(),
        event_id: event_id.into(),
        app_id: 480,
        base_change_number: 1,
        remote_change_number: 2,
        resolution: resolution.into(),
        machine_name: Some("deck".into()),
    }
}

#[test]
fn newer_playtime_snapshot_survives_stale_delivery() {
    let directory = tempfile::tempdir().unwrap();
    let journal = journal(&directory);
    journal.enqueue_playtime(&[playtime(10, 120)]).unwrap();
    let sent = journal.pending_playtime(SCOPE, STEAM_ID, 10).unwrap();
    assert_eq!(values(&sent), vec![playtime(10, 120)]);

    // A newer observation lands while the upload is in flight.
    journal.enqueue_playtime(&[playtime(11, 121)]).unwrap();
    journal.acknowledge_all(&sent).unwrap();

    let pending = journal.pending_playtime(SCOPE, STEAM_ID, 11).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].value.playtime_minutes, 121);
}

#[test]
fn acknowledging_an_unchanged_record_clears_it() {
    let directory = tempfile::tempdir().unwrap();
    let journal = journal(&directory);
    journal.enqueue_playtime(&[playtime(10, 120)]).unwrap();
    let sent = journal.pending_playtime(SCOPE, STEAM_ID, 10).unwrap();
    journal.acknowledge_all(&sent).unwrap();
    assert!(journal.playtime_empty().unwrap());
}

#[test]
fn deferring_backs_off_and_hides_the_record_until_due() {
    let directory = tempfile::tempdir().unwrap();
    let journal = journal(&directory);
    journal.enqueue_playtime(&[playtime(10, 120)]).unwrap();
    let sent = journal.pending_playtime(SCOPE, STEAM_ID, 10).unwrap();
    journal.defer_all(&sent, 100).unwrap();

    assert_eq!(journal.next_playtime_attempt_at(SCOPE).unwrap(), Some(101));

    assert!(journal
        .pending_playtime(SCOPE, STEAM_ID, 100)
        .unwrap()
        .is_empty());
    assert!(journal
        .ready_playtime_accounts(SCOPE, 100)
        .unwrap()
        .is_empty());

    let due = journal.pending_playtime(SCOPE, STEAM_ID, 101).unwrap();
    assert_eq!(due.len(), 1);

    // The second failure backs off further than the first.
    journal.defer_all(&due, 200).unwrap();
    assert_eq!(journal.next_playtime_attempt_at(SCOPE).unwrap(), Some(202));
    assert!(journal
        .pending_playtime(SCOPE, STEAM_ID, 201)
        .unwrap()
        .is_empty());
    assert_eq!(
        journal
            .pending_playtime(SCOPE, STEAM_ID, 202)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_new_observation_clears_the_backoff() {
    let directory = tempfile::tempdir().unwrap();
    let journal = journal(&directory);
    journal.enqueue_playtime(&[playtime(10, 120)]).unwrap();
    let sent = journal.pending_playtime(SCOPE, STEAM_ID, 10).unwrap();
    journal.defer_all(&sent, 1_000).unwrap();
    assert!(journal
        .pending_playtime(SCOPE, STEAM_ID, 1_000)
        .unwrap()
        .is_empty());

    journal.enqueue_playtime(&[playtime(11, 121)]).unwrap();
    assert_eq!(
        journal.pending_playtime(SCOPE, STEAM_ID, 11).unwrap().len(),
        1
    );
}

#[test]
fn ready_accounts_cover_both_playtime_and_sessions() {
    let directory = tempfile::tempdir().unwrap();
    let journal = journal(&directory);
    assert!(journal
        .ready_playtime_accounts(SCOPE, 10)
        .unwrap()
        .is_empty());

    journal
        .enqueue_playtime_sessions(&[playtime_session("session-1")])
        .unwrap();
    assert_eq!(
        journal.ready_playtime_accounts(SCOPE, 10).unwrap(),
        vec![STEAM_ID.to_owned()]
    );

    journal.enqueue_playtime(&[playtime(10, 120)]).unwrap();
    assert_eq!(
        journal.ready_playtime_accounts(SCOPE, 10).unwrap(),
        vec![STEAM_ID.to_owned()],
        "an account with both kinds is reported once"
    );
    assert!(journal
        .ready_playtime_accounts("other-scope", 10)
        .unwrap()
        .is_empty());
}

#[test]
fn playtime_sessions_are_durable_idempotent_and_exactly_acknowledged() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sync-journal.stry");
    let first = playtime_session("session-1");
    {
        let journal = SyncJournal::open(&path).unwrap();
        assert_eq!(
            journal
                .enqueue_playtime_sessions(std::slice::from_ref(&first))
                .unwrap(),
            1
        );
        assert_eq!(
            journal
                .enqueue_playtime_sessions(std::slice::from_ref(&first))
                .unwrap(),
            0,
            "a replayed session must not be queued twice"
        );
    }

    let reopened = SyncJournal::open(&path).unwrap();
    let pending = reopened
        .pending_playtime_sessions(SCOPE, STEAM_ID, 1_800_000_125)
        .unwrap();
    assert_eq!(values(&pending), vec![first]);
    reopened.acknowledge_all(&pending).unwrap();
    assert_eq!(reopened.playtime_session_len().unwrap(), 0);
}

#[test]
fn schemas_are_attributed_to_the_backend_scope_once_it_is_known() {
    let directory = tempfile::tempdir().unwrap();
    let journal = journal(&directory);
    let schema = AchievementSchema {
        owner_scope: String::new(),
        app_id: 620,
        language: "english".into(),
        schema_version: Some("abc".into()),
        content: vec![1, 2, 3],
    };
    journal.enqueue_schema(&schema, 10).unwrap();
    assert!(journal.pending_schemas(10, SCOPE).unwrap().is_empty());

    journal.attribute_pending_schemas(SCOPE).unwrap();
    assert_eq!(journal.next_schema_attempt_at(SCOPE).unwrap(), Some(0));
    let pending = journal.pending_schemas(10, SCOPE).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].value.content, vec![1, 2, 3]);

    journal.acknowledge_all(&pending).unwrap();
    assert!(journal.pending_schemas(10, SCOPE).unwrap().is_empty());
    assert_eq!(journal.next_schema_attempt_at(SCOPE).unwrap(), None);
}

#[test]
fn conflicts_are_attributed_to_the_backend_scope_once_it_is_known() {
    let directory = tempfile::tempdir().unwrap();
    let journal = journal(&directory);
    let mut conflict = conflict("conflict-staged", "kept_cloud");
    conflict.owner_scope = "credential-scope".into();
    journal.enqueue_conflict(&conflict, 10).unwrap();

    assert!(journal
        .pending_cloud_conflicts(10, SCOPE)
        .unwrap()
        .is_empty());
    journal
        .attribute_pending_conflicts("credential-scope", SCOPE)
        .unwrap();

    let pending = journal.pending_cloud_conflicts(10, SCOPE).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].value.event_id, conflict.event_id);
    assert_eq!(pending[0].value.owner_scope, SCOPE);
}

#[test]
fn stats_commit_marker_survives_reopen_and_completes_to_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sync-journal.stry");
    let commit = stats_commit("commit-1", 100);
    {
        SyncJournal::open(&path)
            .unwrap()
            .enqueue_stats_commit(&commit)
            .unwrap();
    }

    let reopened = SyncJournal::open(&path).unwrap();
    assert_eq!(
        reopened.pending_stats_commit(SCOPE, STEAM_ID, 620).unwrap(),
        Some(commit)
    );

    let snapshot = steam_snapshot("commit-1", 101);
    assert_eq!(
        reopened
            .next_stats_snapshot_attempt_at(SCOPE, STEAM_ID)
            .unwrap(),
        None,
        "a marker awaiting Steam is not an upload retry"
    );
    assert!(reopened.complete_stats_snapshot(&snapshot).unwrap());
    assert_eq!(
        reopened
            .next_stats_snapshot_attempt_at(SCOPE, STEAM_ID)
            .unwrap(),
        Some(0)
    );
    assert_eq!(
        values(
            &reopened
                .pending_stats_snapshots(SCOPE, STEAM_ID, 101)
                .unwrap()
        ),
        vec![snapshot]
    );
    assert!(reopened
        .stats_sync_pending(SCOPE, STEAM_ID, 620, 0, i64::MAX)
        .unwrap());
    assert_eq!(
        reopened.pending_stats_commit(SCOPE, STEAM_ID, 620).unwrap(),
        None,
        "a completed record is no longer awaiting Steam"
    );
}

#[test]
fn stats_snapshot_without_a_commit_is_ignored() {
    let directory = tempfile::tempdir().unwrap();
    let journal = journal(&directory);

    assert!(!journal
        .complete_stats_snapshot(&steam_snapshot("unsolicited", 101))
        .unwrap());
    assert_eq!(journal.stats_len().unwrap(), 0);
    assert!(journal
        .pending_stats_snapshots(SCOPE, STEAM_ID, i64::MAX)
        .unwrap()
        .is_empty());
}

#[test]
fn successful_stats_delivery_is_removed_after_acknowledgement() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sync-journal.stry");
    let snapshot = steam_snapshot("commit-1", 101);
    {
        let journal = SyncJournal::open(&path).unwrap();
        journal
            .enqueue_stats_commit(&stats_commit("commit-1", 100))
            .unwrap();
        assert!(journal.complete_stats_snapshot(&snapshot).unwrap());
        let pending = journal
            .pending_stats_snapshots(SCOPE, STEAM_ID, 101)
            .unwrap();
        journal.acknowledge(&pending[0]).unwrap();
        assert!(!journal
            .stats_sync_pending(SCOPE, STEAM_ID, 620, 0, i64::MAX)
            .unwrap());
    }

    let reopened = SyncJournal::open(&path).unwrap();
    assert!(reopened
        .pending_stats_snapshots(SCOPE, STEAM_ID, i64::MAX)
        .unwrap()
        .is_empty());
}

#[test]
fn concurrent_enqueue_keeps_one_row_per_identity() {
    use std::sync::{Arc, Barrier};

    let directory = tempfile::tempdir().unwrap();
    let journal = Arc::new(journal(&directory));
    let threads = 8;
    let barrier = Arc::new(Barrier::new(threads));

    // persy locks per record id and an insert always mints a fresh one, so
    // without a writer lock every thread's check would miss the others' rows.
    let handles = (0..threads)
        .map(|index| {
            let journal = Arc::clone(&journal);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                journal
                    .enqueue_stats_commit(&stats_commit(&format!("commit-{index}"), 100))
                    .unwrap();
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(journal.stats_len().unwrap(), 1);
    assert!(journal
        .pending_stats_commit(SCOPE, STEAM_ID, 620)
        .unwrap()
        .is_some());
}

#[test]
fn stale_stats_snapshot_cannot_overwrite_a_new_commit_marker() {
    let directory = tempfile::tempdir().unwrap();
    let journal = journal(&directory);
    let second = stats_commit("commit-2", 102);
    journal
        .enqueue_stats_commit(&stats_commit("commit-1", 100))
        .unwrap();
    journal.enqueue_stats_commit(&second).unwrap();

    assert!(!journal
        .complete_stats_snapshot(&steam_snapshot("commit-1", 103))
        .unwrap());
    assert_eq!(
        journal.pending_stats_commit(SCOPE, STEAM_ID, 620).unwrap(),
        Some(second)
    );
}

#[test]
fn stats_snapshot_delivery_is_exact_and_preserves_new_commits() {
    let directory = tempfile::tempdir().unwrap();
    let journal = journal(&directory);
    journal
        .enqueue_stats_commit(&stats_commit("commit-1", 100))
        .unwrap();
    assert!(journal
        .complete_stats_snapshot(&steam_snapshot("commit-1", 101))
        .unwrap());
    let sent = journal
        .pending_stats_snapshots(SCOPE, STEAM_ID, 101)
        .unwrap();

    // Steam commits again while the snapshot upload is in flight.
    let second = stats_commit("commit-2", 102);
    journal.enqueue_stats_commit(&second).unwrap();
    journal.acknowledge(&sent[0]).unwrap();

    assert_eq!(
        journal.pending_stats_commit(SCOPE, STEAM_ID, 620).unwrap(),
        Some(second),
        "settling a stale snapshot must not drop the newer commit"
    );
}

#[test]
fn backend_principal_scope_is_durable_and_credential_specific() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sync-journal.stry");
    {
        let journal = SyncJournal::open(&path).unwrap();
        journal
            .store_backend_principal_scope("credential-a", "principal-a", 100)
            .unwrap();
        journal
            .store_backend_principal_scope("credential-b", "principal-b", 101)
            .unwrap();
        // Re-storing the same credential must not create a second row.
        journal
            .store_backend_principal_scope("credential-a", "principal-a", 102)
            .unwrap();
    }

    let reopened = SyncJournal::open(&path).unwrap();
    assert_eq!(
        reopened
            .load_backend_principal_scope("credential-a")
            .unwrap()
            .as_deref(),
        Some("principal-a")
    );
    assert_eq!(
        reopened
            .load_backend_principal_scope("credential-b")
            .unwrap()
            .as_deref(),
        Some("principal-b")
    );
    assert_eq!(
        reopened
            .load_backend_principal_scope("rotated-credential")
            .unwrap(),
        None
    );
}

#[test]
fn device_identity_and_conflict_are_durable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sync-journal.stry");
    let descriptor = DeviceDescriptor {
        client_id: 7,
        machine_name: "deck".into(),
        os_type: Some(1),
        device_type: Some(2),
    };
    let kept_cloud = conflict("conflict-1", "kept_cloud");
    {
        let journal = SyncJournal::open(&path).unwrap();
        assert!(journal.store_device_descriptor(&descriptor, 10).unwrap());
        journal.enqueue_conflict(&kept_cloud, 10).unwrap();
    }

    let reopened = SyncJournal::open(&path).unwrap();
    assert_eq!(reopened.load_device_descriptor().unwrap(), Some(descriptor));
    assert_eq!(
        values(&reopened.pending_cloud_conflicts(10, SCOPE).unwrap()),
        vec![kept_cloud]
    );
}

#[test]
fn storing_the_device_descriptor_twice_keeps_one_row() {
    let directory = tempfile::tempdir().unwrap();
    let journal = journal(&directory);
    let mut descriptor = DeviceDescriptor {
        client_id: 7,
        machine_name: "deck".into(),
        os_type: Some(1),
        device_type: Some(2),
    };
    assert!(journal.store_device_descriptor(&descriptor, 10).unwrap());
    assert!(!journal.store_device_descriptor(&descriptor, 11).unwrap());
    descriptor.client_id = 9;
    assert!(journal.store_device_descriptor(&descriptor, 12).unwrap());
    assert_eq!(journal.load_device_descriptor().unwrap(), Some(descriptor));
}

#[test]
fn a_new_resolution_supersedes_the_previous_one_for_the_same_app() {
    let directory = tempfile::tempdir().unwrap();
    let journal = journal(&directory);
    journal
        .enqueue_conflict(&conflict("conflict-1", "kept_cloud"), 10)
        .unwrap();
    let second = conflict("conflict-2", "kept_cloud");
    journal.enqueue_conflict(&second, 11).unwrap();

    assert_eq!(journal.conflict_len().unwrap(), 1);
    assert_eq!(
        values(&journal.pending_cloud_conflicts(11, SCOPE).unwrap()),
        vec![second]
    );
}

#[test]
fn local_resolutions_are_bound_to_a_batch_and_never_reported() {
    let directory = tempfile::tempdir().unwrap();
    let journal = journal(&directory);
    let kept_local = conflict("conflict-1", "kept_local");
    journal.enqueue_conflict(&kept_local, 10).unwrap();

    assert!(journal
        .pending_cloud_conflicts(10, SCOPE)
        .unwrap()
        .is_empty());
    let bound = journal.pending_local_conflict(SCOPE, 480, 2).unwrap();
    assert_eq!(
        bound.as_ref().map(|item| item.value.clone()),
        Some(kept_local)
    );
    assert!(journal
        .pending_local_conflict(SCOPE, 480, 3)
        .unwrap()
        .is_none());

    journal.acknowledge(&bound.unwrap()).unwrap();
    assert_eq!(journal.conflict_len().unwrap(), 0);
}
