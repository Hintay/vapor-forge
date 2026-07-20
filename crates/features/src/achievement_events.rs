use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AchievementId {
    owner_steam_id64: u64,
    app_id: u32,
    key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingAchievement {
    Unlock {
        owner_steam_id64: u64,
        app_id: u32,
        key: String,
        observed_at: i64,
        unlocked_at: i64,
    },
    Clear {
        owner_steam_id64: u64,
        app_id: u32,
        key: String,
        observed_at: i64,
    },
    Progress {
        owner_steam_id64: u64,
        app_id: u32,
        key: String,
        current: u32,
        maximum: u32,
        observed_at: i64,
    },
}

impl PendingAchievement {
    fn id(&self) -> AchievementId {
        match self {
            Self::Unlock {
                owner_steam_id64,
                app_id,
                key,
                ..
            }
            | Self::Clear {
                owner_steam_id64,
                app_id,
                key,
                ..
            }
            | Self::Progress {
                owner_steam_id64,
                app_id,
                key,
                ..
            } => AchievementId {
                owner_steam_id64: *owner_steam_id64,
                app_id: *app_id,
                key: key.clone(),
            },
        }
    }
}

#[derive(Default)]
pub struct AchievementCommitBuffer {
    unlocked: HashSet<AchievementId>,
    baselines: HashSet<(u64, u32)>,
    intents: HashMap<AchievementId, (bool, i64)>,
    observed_progress: HashMap<AchievementId, (u32, u32)>,
    pending_unlocks: HashMap<AchievementId, (i64, i64)>,
    pending_clears: HashMap<AchievementId, i64>,
    pending_progress: HashMap<AchievementId, (u32, u32, i64)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotObservation {
    Baseline,
    Updated,
}

impl AchievementCommitBuffer {
    pub fn stage_unlock(
        &mut self,
        owner_steam_id64: u64,
        app_id: u32,
        key: &str,
        observed_at: i64,
    ) -> bool {
        let Some(id) = valid_id(owner_steam_id64, app_id, key) else {
            return false;
        };
        if observed_at <= 0 {
            return false;
        }
        self.observed_progress.remove(&id);
        self.pending_progress.remove(&id);
        self.intents.insert(id, (true, observed_at)) != Some((true, observed_at))
    }

    pub fn stage_clear(
        &mut self,
        owner_steam_id64: u64,
        app_id: u32,
        key: &str,
        observed_at: i64,
    ) -> bool {
        let Some(id) = valid_id(owner_steam_id64, app_id, key) else {
            return false;
        };
        if observed_at <= 0 {
            return false;
        }
        self.intents.insert(id, (false, observed_at)) != Some((false, observed_at))
    }

    pub fn commit(&mut self, owner_steam_id64: u64, app_id: u32) {
        let intents = self
            .intents
            .iter()
            .filter(|(id, _)| id.owner_steam_id64 == owner_steam_id64 && id.app_id == app_id)
            .map(|(id, value)| (id.clone(), *value))
            .collect::<Vec<_>>();
        for (id, (unlocked, observed_at)) in intents {
            self.intents.remove(&id);
            if unlocked {
                self.pending_clears.remove(&id);
                if self.unlocked.insert(id.clone()) {
                    self.pending_unlocks
                        .insert(id.clone(), (observed_at, observed_at));
                }
                self.observed_progress.remove(&id);
                self.pending_progress.remove(&id);
            } else {
                self.record_clear(id, observed_at);
            }
        }
    }

    pub fn observe_snapshot(
        &mut self,
        owner_steam_id64: u64,
        app_id: u32,
        unlocked_achievements: &[(String, i64)],
        observed_at: i64,
    ) -> Option<SnapshotObservation> {
        if owner_steam_id64 == 0 || app_id == 0 || observed_at <= 0 {
            return None;
        }
        let latest = unlocked_achievements
            .iter()
            .filter_map(|(key, unlocked_at)| {
                valid_id(owner_steam_id64, app_id, key).map(|id| {
                    (
                        id,
                        if *unlocked_at > 0 {
                            *unlocked_at
                        } else {
                            observed_at
                        },
                    )
                })
            })
            .collect::<HashMap<_, _>>();
        let latest_ids = latest.keys().cloned().collect::<HashSet<_>>();
        let baseline = self.baselines.insert((owner_steam_id64, app_id));
        let previous = self
            .unlocked
            .iter()
            .filter(|id| id.owner_steam_id64 == owner_steam_id64 && id.app_id == app_id)
            .cloned()
            .collect::<HashSet<_>>();

        if baseline {
            for (id, unlocked_at) in latest {
                self.unlocked.insert(id.clone());
                self.pending_unlocks.insert(id, (observed_at, unlocked_at));
            }
            return Some(SnapshotObservation::Baseline);
        }

        for id in previous.difference(&latest_ids) {
            self.record_clear(id.clone(), observed_at);
        }
        for id in latest_ids.difference(&previous) {
            self.unlocked.insert(id.clone());
            self.pending_unlocks
                .insert(id.clone(), (observed_at, latest[id]));
        }
        Some(SnapshotObservation::Updated)
    }

    pub fn stage_progress(
        &mut self,
        owner_steam_id64: u64,
        app_id: u32,
        key: &str,
        current: u32,
        maximum: u32,
        observed_at: i64,
    ) -> bool {
        let Some(id) = valid_id(owner_steam_id64, app_id, key) else {
            return false;
        };
        if observed_at <= 0 || maximum == 0 || current > maximum || self.unlocked.contains(&id) {
            return false;
        }
        let progress = (current, maximum);
        if self.observed_progress.get(&id) == Some(&progress) {
            return false;
        }
        self.observed_progress.insert(id.clone(), progress);
        self.pending_progress
            .insert(id, (current, maximum, observed_at));
        true
    }

    fn record_clear(&mut self, id: AchievementId, observed_at: i64) {
        self.unlocked.remove(&id);
        self.intents.remove(&id);
        self.observed_progress.remove(&id);
        self.pending_unlocks.remove(&id);
        self.pending_progress.remove(&id);
        self.pending_clears.insert(id, observed_at);
    }

    pub fn pending_for_app(&self, owner_steam_id64: u64, app_id: u32) -> Vec<PendingAchievement> {
        let mut pending = self
            .pending_unlocks
            .iter()
            .filter(|(id, _)| id.owner_steam_id64 == owner_steam_id64 && id.app_id == app_id)
            .map(
                |(id, &(observed_at, unlocked_at))| PendingAchievement::Unlock {
                    owner_steam_id64,
                    app_id,
                    key: id.key.clone(),
                    observed_at,
                    unlocked_at,
                },
            )
            .collect::<Vec<_>>();
        pending.extend(
            self.pending_clears
                .iter()
                .filter(|(id, _)| id.owner_steam_id64 == owner_steam_id64 && id.app_id == app_id)
                .map(|(id, &observed_at)| PendingAchievement::Clear {
                    owner_steam_id64,
                    app_id,
                    key: id.key.clone(),
                    observed_at,
                }),
        );
        pending.extend(
            self.pending_progress
                .iter()
                .filter(|(id, _)| id.owner_steam_id64 == owner_steam_id64 && id.app_id == app_id)
                .map(
                    |(id, &(current, maximum, observed_at))| PendingAchievement::Progress {
                        owner_steam_id64,
                        app_id,
                        key: id.key.clone(),
                        current,
                        maximum,
                        observed_at,
                    },
                ),
        );
        pending
    }

    pub fn pending_progress(
        &self,
        owner_steam_id64: u64,
        app_id: u32,
        key: &str,
    ) -> Option<PendingAchievement> {
        let id = valid_id(owner_steam_id64, app_id, key)?;
        let &(current, maximum, observed_at) = self.pending_progress.get(&id)?;
        Some(PendingAchievement::Progress {
            owner_steam_id64,
            app_id,
            key: key.to_owned(),
            current,
            maximum,
            observed_at,
        })
    }

    pub fn mark_sent(&mut self, pending: &PendingAchievement) {
        let id = pending.id();
        match pending {
            PendingAchievement::Unlock {
                observed_at,
                unlocked_at,
                ..
            } => {
                if self.pending_unlocks.get(&id) == Some(&(*observed_at, *unlocked_at)) {
                    self.pending_unlocks.remove(&id);
                }
            }
            PendingAchievement::Progress {
                current,
                maximum,
                observed_at,
                ..
            } => {
                if self.pending_progress.get(&id) == Some(&(*current, *maximum, *observed_at)) {
                    self.pending_progress.remove(&id);
                }
            }
            PendingAchievement::Clear { observed_at, .. } => {
                if self.pending_clears.get(&id) == Some(observed_at) {
                    self.pending_clears.remove(&id);
                }
            }
        }
    }
}

fn valid_id(owner_steam_id64: u64, app_id: u32, key: &str) -> Option<AchievementId> {
    (owner_steam_id64 != 0 && app_id != 0 && !key.is_empty()).then(|| AchievementId {
        owner_steam_id64,
        app_id,
        key: key.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_imports_baseline_then_reports_new_unlocks() {
        let mut buffer = AchievementCommitBuffer::default();
        assert_eq!(
            buffer.observe_snapshot(7, 736260, &[("EXISTING".into(), 8)], 10),
            Some(SnapshotObservation::Baseline)
        );
        assert_eq!(
            buffer.pending_for_app(7, 736260),
            [PendingAchievement::Unlock {
                owner_steam_id64: 7,
                app_id: 736260,
                key: "EXISTING".into(),
                observed_at: 10,
                unlocked_at: 8,
            }]
        );
        let baseline = buffer.pending_for_app(7, 736260).remove(0);
        buffer.mark_sent(&baseline);

        assert_eq!(
            buffer.observe_snapshot(7, 736260, &[("EXISTING".into(), 8), ("NEW".into(), 11)], 12,),
            Some(SnapshotObservation::Updated)
        );
        assert_eq!(
            buffer.pending_for_app(7, 736260),
            [PendingAchievement::Unlock {
                owner_steam_id64: 7,
                app_id: 736260,
                key: "NEW".into(),
                observed_at: 12,
                unlocked_at: 11,
            }]
        );
    }

    #[test]
    fn commits_only_the_requested_app() {
        let mut buffer = AchievementCommitBuffer::default();
        assert!(buffer.stage_unlock(1, 480, "FIRST", 10));
        assert!(buffer.stage_progress(1, 620, "SECOND", 2, 10, 11));
        buffer.commit(1, 480);

        let app_480 = buffer.pending_for_app(1, 480);
        assert_eq!(
            app_480,
            [PendingAchievement::Unlock {
                owner_steam_id64: 1,
                app_id: 480,
                key: "FIRST".into(),
                observed_at: 10,
                unlocked_at: 10,
            }]
        );
        buffer.mark_sent(&app_480[0]);
        assert!(buffer.pending_for_app(1, 480).is_empty());
        assert_eq!(buffer.pending_for_app(1, 620).len(), 1);
    }

    #[test]
    fn store_applies_the_last_set_or_clear_intent() {
        let mut buffer = AchievementCommitBuffer::default();
        assert_eq!(
            buffer.observe_snapshot(1, 480, &[], 10),
            Some(SnapshotObservation::Baseline)
        );
        assert!(buffer.stage_unlock(1, 480, "COLLECT", 11));
        assert!(buffer.stage_clear(1, 480, "COLLECT", 12));
        buffer.commit(1, 480);
        assert_eq!(
            buffer.pending_for_app(1, 480),
            [PendingAchievement::Clear {
                owner_steam_id64: 1,
                app_id: 480,
                key: "COLLECT".into(),
                observed_at: 12,
            }]
        );
        let clear = buffer.pending_for_app(1, 480).remove(0);
        buffer.mark_sent(&clear);

        assert!(buffer.stage_unlock(1, 480, "COLLECT", 13));
        buffer.commit(1, 480);
        assert_eq!(buffer.pending_for_app(1, 480).len(), 1);
    }

    #[test]
    fn snapshot_difference_queues_a_clear() {
        let mut buffer = AchievementCommitBuffer::default();
        buffer.observe_snapshot(1, 480, &[("COLLECT".into(), 8)], 10);
        let baseline = buffer.pending_for_app(1, 480).remove(0);
        buffer.mark_sent(&baseline);

        assert_eq!(
            buffer.observe_snapshot(1, 480, &[], 11),
            Some(SnapshotObservation::Updated)
        );
        assert_eq!(
            buffer.pending_for_app(1, 480),
            [PendingAchievement::Clear {
                owner_steam_id64: 1,
                app_id: 480,
                key: "COLLECT".into(),
                observed_at: 11,
            }]
        );
    }

    #[test]
    fn coalesces_progress_without_losing_observation_time() {
        let mut buffer = AchievementCommitBuffer::default();
        assert!(buffer.stage_progress(1, 480, "COLLECT", 1, 10, 10));
        assert!(!buffer.stage_progress(1, 480, "COLLECT", 1, 10, 11));
        assert!(buffer.stage_progress(1, 480, "COLLECT", 3, 10, 12));
        assert_eq!(
            buffer.pending_for_app(1, 480),
            [PendingAchievement::Progress {
                owner_steam_id64: 1,
                app_id: 480,
                key: "COLLECT".into(),
                current: 3,
                maximum: 10,
                observed_at: 12,
            }]
        );
    }

    #[test]
    fn isolates_pending_events_by_steam_account() {
        let mut buffer = AchievementCommitBuffer::default();
        assert!(buffer.stage_unlock(1, 480, "SAME_KEY", 10));
        assert!(buffer.stage_unlock(2, 480, "SAME_KEY", 11));
        buffer.commit(1, 480);
        buffer.commit(2, 480);

        assert_eq!(buffer.pending_for_app(1, 480).len(), 1);
        assert_eq!(buffer.pending_for_app(2, 480).len(), 1);
        assert!(buffer.pending_for_app(3, 480).is_empty());
    }
}
