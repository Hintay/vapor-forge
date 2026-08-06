pub(super) mod html_window;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionResult {
    Executed,
    Terminated,
}

pub(super) fn drain() {
    retain_live_window_contexts();
    prime_windows();
    retain_live_window_contexts();

    let windows = crate::ui::reverse_bridge::ready_windows();
    if windows.is_empty() {
        return;
    }

    pump_cloud_conflicts(&windows);

    let toasts = vapor_forge_features::toast::take_pending();
    for (index, toast) in toasts.iter().enumerate() {
        let script = vapor_forge_features::toast::toast_script(toast);
        match execute_on_windows(&windows, &script) {
            ExecutionResult::Executed => {}
            _ => {
                vapor_forge_features::toast::restore_pending(&toasts[index..]);
                break;
            }
        }
    }
}

fn retain_live_window_contexts() {
    if let Some(queue) = crate::netpacket::cloud_rpc_queue() {
        queue.retain_conflict_ui_windows(&crate::ui::reverse_bridge::live_window_generations());
    }
}

fn prime_windows() {
    for (window, generation) in crate::ui::reverse_bridge::pending_bridge_windows() {
        match html_window::execute_javascript_on(
            window,
            vapor_forge_features::toast::bridge_script(),
        ) {
            html_window::ExecuteResult::Executed => {
                crate::ui::reverse_bridge::mark_bridge_dispatched(window, generation);
            }
            html_window::ExecuteResult::Unavailable => tracing::warn!(
                window = format_args!("{window:#x}"),
                "steamui: ExecuteJavaScript is unavailable"
            ),
        }
    }
}

fn execute_on_windows(windows: &[(usize, u64)], script: &str) -> ExecutionResult {
    let mut executed = false;
    for &(window, generation) in windows {
        match execute_on_window(window, generation, script) {
            ExecutionResult::Executed => executed = true,
            ExecutionResult::Terminated => {}
        }
    }
    if executed {
        ExecutionResult::Executed
    } else {
        ExecutionResult::Terminated
    }
}

fn execute_on_window(window: usize, generation: u64, script: &str) -> ExecutionResult {
    match html_window::execute_javascript_on(window, script) {
        html_window::ExecuteResult::Executed => ExecutionResult::Executed,
        html_window::ExecuteResult::Unavailable => {
            tracing::warn!(
                window = format_args!("{window:#x}"),
                generation,
                "steamui: registered window cannot execute JavaScript"
            );
            ExecutionResult::Terminated
        }
    }
}

fn pump_cloud_conflicts(windows: &[(usize, u64)]) {
    let Some(queue) = crate::netpacket::cloud_rpc_queue() else {
        return;
    };

    for callback in crate::ui::reverse_bridge::take_callbacks() {
        if !windows
            .iter()
            .any(|(_, generation)| *generation == callback.window_generation)
        {
            continue;
        }
        let context = conflict_context(callback.window_generation);
        match callback.kind {
            crate::ui::reverse_bridge::CallbackKind::Receipt => {
                let confirmed = queue.acknowledge_conflict_ack(context, callback.as_str());
                tracing::info!(
                    window_generation = callback.window_generation,
                    confirmed,
                    "steamui: cloud conflict acknowledgement receipt"
                );
            }
            crate::ui::reverse_bridge::CallbackKind::Retry => {
                let scheduled = queue.retry_conflict_ack(context, callback.as_str())
                    || queue.retry_conflict_dialog(context, callback.as_str());
                tracing::info!(
                    window_generation = callback.window_generation,
                    scheduled,
                    "steamui: cloud conflict delivery retry"
                );
            }
            crate::ui::reverse_bridge::CallbackKind::Choice => {
                let result = queue.submit_conflict_choice(callback.as_str(), context);
                tracing::info!(
                    window_generation = callback.window_generation,
                    ?result,
                    "steamui: cloud conflict choice received"
                );
                if result != vapor_forge_cloud_rpc::ConflictSubmitResult::Accepted {
                    queue.queue_conflict_ack(
                        context,
                        vapor_forge_cloud_rpc::ConflictUiAck {
                            token: callback.as_str().to_owned(),
                            app_id: 0,
                            accepted: false,
                            error: "stale_choice".into(),
                            resume_launch: false,
                            cancel_launch: false,
                        },
                    );
                }
            }
        }
    }

    for &(window, generation) in windows {
        let context = conflict_context(generation);
        let dialogs = queue.conflict_dialogs(context);
        let acks = queue.conflict_ack_deliveries(context);
        if dialogs.is_empty() && acks.is_empty() {
            continue;
        }
        let result = execute_conflict_update(window, generation, &dialogs, &acks);
        if result != ExecutionResult::Executed {
            queue.retry_conflict_ui_context(context);
            for ack in &acks {
                queue.defer_conflict_ack(context, &ack.token);
            }
        }
    }
}

fn conflict_context(window_generation: u64) -> vapor_forge_cloud_rpc::ConflictUiContext {
    let config = crate::client::install::config();
    vapor_forge_cloud_rpc::ConflictUiContext {
        steam_id64: vapor_forge_features::identity::steam_id(),
        identity_generation: vapor_forge_features::identity::generation(),
        connection_generation: crate::client::network::injection_generation(),
        window_generation,
        cloud_scope: vapor_forge_cloud_rpc::conflict_ui_scope(&config),
    }
}

fn execute_conflict_update(
    window: usize,
    generation: u64,
    dialogs: &[vapor_forge_cloud_rpc::ConflictDialog],
    acks: &[vapor_forge_cloud_rpc::ConflictUiAck],
) -> ExecutionResult {
    let Ok(dialogs) = serde_json::to_string(dialogs) else {
        return ExecutionResult::Terminated;
    };
    let Ok(acks) = serde_json::to_string(acks) else {
        return ExecutionResult::Terminated;
    };
    let script = conflict_update_script(&dialogs, &acks);
    execute_on_window(window, generation, &script)
}

fn conflict_update_script(dialogs: &str, acks: &str) -> String {
    format!(
        "(function(){{var a=({acks});var d=({dialogs});var r=function(v){{try{{window.SteamClient.Apps.VaporForgeRetryCloudConflict(v.token);}}catch(_){{}}}};var q=function(v){{r({{token:v.cancel_token}});}};try{{var b=window.VaporForgeUIBridge||window.VaporForgeToastBridge;a.forEach(function(v){{try{{if(!b||typeof b.ackCloudConflict!=='function'||!b.ackCloudConflict(v))r(v);}}catch(_){{r(v);}}}});d.forEach(function(v){{try{{if(!b||typeof b.showCloudConflict!=='function'||!b.showCloudConflict(v))q(v);}}catch(e){{q(v);try{{console.log('[VaporForgeUI] cloud conflict dialog failed: '+e);}}catch(_){{}}}}}});}}catch(e){{a.forEach(r);d.forEach(q);try{{console.log('[VaporForgeUI] conflict update failed: '+e);}}catch(_){{}}}}}})();"
    )
}

pub fn request_pump() {
    vapor_forge_features::toast::request_ui_work();
}

#[cfg(test)]
mod tests {
    use super::conflict_update_script;

    #[test]
    fn conflict_update_isolates_ack_and_dialog_failures_without_a_timer() {
        let script = conflict_update_script("[{\"app_id\":480}]", "[{\"token\":\"ack\"}]");
        let ack_loop = script.find("a.forEach(function(v)").unwrap();
        let dialog_loop = script.find("d.forEach(function(v)").unwrap();

        assert!(ack_loop < dialog_loop);
        assert!(script.contains("catch(_){r(v);}"));
        assert!(script.contains("var q=function(v){r({token:v.cancel_token});}"));
        assert!(script.contains("!b.showCloudConflict(v))q(v)"));
        assert!(script.contains("catch(e){q(v);"));
        assert!(script.contains("cloud conflict dialog failed"));
        assert!(script.contains("catch(e){a.forEach(r);d.forEach(q);"));
        assert!(!script.contains("setTimeout"));
        assert!(!script.contains("setInterval"));
    }
}
