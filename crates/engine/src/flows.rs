//! Registry of active relays (TCP connections and UDP sessions) by outbound
//! interface, so that every flow on an adapter can be torn down the moment the
//! adapter becomes unavailable. Apps then reconnect and get a fresh routing
//! decision instead of hanging on a dead link.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

use crate::policy::Proto;

struct Entry {
    if_index: u32,
    proto: Proto,
    kill: oneshot::Sender<()>,
}

#[derive(Default)]
pub struct FlowTable {
    next_id: AtomicU64,
    entries: Mutex<HashMap<u64, Entry>>,
}

/// Removes the flow from the table when the relay ends.
pub struct FlowGuard {
    table: Arc<FlowTable>,
    id: u64,
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.table.entries.lock().unwrap().remove(&self.id);
    }
}

impl FlowTable {
    /// Registers a flow leaving through `if_index`. The receiver fires when the
    /// flow must be torn down; keep the guard alive for as long as the relay runs.
    pub fn register(self: &Arc<Self>, if_index: u32, proto: Proto) -> (FlowGuard, oneshot::Receiver<()>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (kill, rx) = oneshot::channel();
        self.entries.lock().unwrap().insert(id, Entry { if_index, proto, kill });
        (FlowGuard { table: self.clone(), id }, rx)
    }

    /// Tears down every flow on `if_index`; returns how many were signalled.
    pub fn reset_interface(&self, if_index: u32) -> usize {
        let mut entries = self.entries.lock().unwrap();
        let ids: Vec<u64> = entries
            .iter()
            .filter(|(_, e)| e.if_index == if_index)
            .map(|(&id, _)| id)
            .collect();
        for id in &ids {
            if let Some(entry) = entries.remove(id) {
                let _ = entry.kill.send(());
            }
        }
        ids.len()
    }

    /// `(if_index, proto)` of every active flow.
    pub fn active(&self) -> Vec<(u32, Proto)> {
        self.entries.lock().unwrap().values().map(|e| (e.if_index, e.proto)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_only_hits_the_given_interface() {
        let table = Arc::new(FlowTable::default());
        let (_a, mut kill_a) = table.register(7, Proto::Tcp);
        let (_b, mut kill_b) = table.register(7, Proto::Udp);
        let (_c, mut kill_c) = table.register(9, Proto::Tcp);

        assert_eq!(table.reset_interface(7), 2);
        assert!(kill_a.try_recv().is_ok());
        assert!(kill_b.try_recv().is_ok());
        assert!(kill_c.try_recv().is_err(), "flow on another interface must survive");
        assert_eq!(table.active(), vec![(9, Proto::Tcp)]);
        assert_eq!(table.reset_interface(7), 0, "already reset");
    }

    #[test]
    fn guard_removes_finished_flows() {
        let table = Arc::new(FlowTable::default());
        let (guard, _kill) = table.register(3, Proto::Tcp);
        assert_eq!(table.active().len(), 1);
        drop(guard);
        assert!(table.active().is_empty());
        assert_eq!(table.reset_interface(3), 0);
    }
}
