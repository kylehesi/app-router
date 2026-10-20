//! Watches for network changes and tears down the flows on any adapter that
//! stops being usable (unplugged, disconnected, lost its gateway). Apps then
//! reconnect right away and get a fresh routing decision, typically onto the
//! rule's fallback, instead of hanging until their own timeouts.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use router_engine::flows::FlowTable;
use tokio::sync::{watch, Notify};
use tracing::{info, warn};

use crate::policy::RulePolicy;

/// Windows fires several notifications per real change; wait for them to settle.
const DEBOUNCE: Duration = Duration::from_millis(500);
/// Safety net in case a notification is missed.
const RECHECK: Duration = Duration::from_secs(5);

pub async fn run(policy: Arc<RulePolicy>, flows: Arc<FlowTable>, mut shutdown: watch::Receiver<bool>) {
    let changed = Arc::new(Notify::new());
    let _watcher = match router_sys::notify::watch_changes({
        let changed = changed.clone();
        move || changed.notify_one()
    }) {
        Ok(watcher) => Some(watcher),
        Err(e) => {
            warn!("network change notifications unavailable, checking every {RECHECK:?}: {e}");
            None
        }
    };

    let mut state = Snapshot::default();
    loop {
        if let Some(next) = snapshot(&policy).await {
            for &if_index in state.usable.difference(&next.usable) {
                let reset = flows.reset_interface(if_index);
                let name = state.name(if_index);
                info!(if_index, adapter = %name, reset, "adapter unavailable, its connections were reset");
            }
            for &if_index in next.usable.difference(&state.usable) {
                info!(if_index, adapter = %next.name(if_index), "adapter available");
            }
            state = next;
        }

        tokio::select! {
            _ = changed.notified() => tokio::time::sleep(DEBOUNCE).await,
            _ = tokio::time::sleep(RECHECK) => {}
            _ = shutdown.changed() => return,
        }
    }
}

#[derive(Default)]
struct Snapshot {
    usable: BTreeSet<u32>,
    names: HashMap<u32, String>,
}

impl Snapshot {
    fn name(&self, if_index: u32) -> String {
        self.names.get(&if_index).cloned().unwrap_or_else(|| format!("#{if_index}"))
    }
}

/// Fresh adapter list (blocking Windows calls, so off the async threads).
async fn snapshot(policy: &Arc<RulePolicy>) -> Option<Snapshot> {
    let policy = policy.clone();
    tokio::task::spawn_blocking(move || {
        let adapters = policy.refresh();
        Snapshot {
            usable: policy.usable_interfaces(&adapters),
            names: adapters.iter().map(|a| (a.if_index, a.display_name())).collect(),
        }
    })
    .await
    .ok()
}
