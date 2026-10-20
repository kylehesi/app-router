//! Answers the engine's per-connection question: socket -> PID -> exe -> rule -> adapter.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use router_common::{AdapterInfo, Fallback};
use router_engine::{Flow, Policy, Proto, Route};
use tracing::{debug, warn};

use crate::rules::RuleStore;

/// Maximum age of the adapter list (adapters get plugged in, unplugged, disconnected).
const ADAPTER_CACHE_TTL: Duration = Duration::from_secs(3);

pub struct RulePolicy {
    rules: Arc<RuleStore>,
    adapters: Mutex<Option<(Instant, Arc<Vec<AdapterInfo>>)>>,
    force_refresh: AtomicBool,
    tun_if_index: AtomicU32,
    /// For testing: send every connection to this adapter, ignoring the rules.
    force: Option<u32>,
}

impl RulePolicy {
    pub fn new(rules: Arc<RuleStore>, force: Option<u32>) -> Self {
        Self {
            rules,
            adapters: Mutex::new(None),
            force_refresh: AtomicBool::new(false),
            tun_if_index: AtomicU32::new(0),
            force,
        }
    }

    /// Called once the engine starts; the TUN must never be picked as the "default adapter".
    pub fn set_tun_if_index(&self, if_index: u32) {
        self.tun_if_index.store(if_index, Ordering::Relaxed);
    }

    /// Drops the cached adapter list and reads a fresh one (after a network change).
    pub fn refresh(&self) -> Arc<Vec<AdapterInfo>> {
        // The stale list is kept so a failed refresh can still fall back to it.
        self.force_refresh.store(true, Ordering::Relaxed);
        self.adapters()
    }

    /// Interfaces that can carry traffic right now.
    pub fn usable_interfaces(&self, adapters: &[AdapterInfo]) -> BTreeSet<u32> {
        adapters.iter().filter(|a| self.usable(a)).map(|a| a.if_index).collect()
    }

    fn adapters(&self) -> Arc<Vec<AdapterInfo>> {
        let mut cache = self.adapters.lock().unwrap();
        let forced = self.force_refresh.swap(false, Ordering::Relaxed);
        if let Some((at, list)) = cache.as_ref() {
            if !forced && at.elapsed() < ADAPTER_CACHE_TTL {
                return list.clone();
            }
        }
        let list = match router_sys::adapters::list_adapters() {
            Ok(list) => Arc::new(list),
            Err(e) => {
                warn!("failed to list adapters: {e}");
                // Keep using the stale list if there is one; otherwise an empty list.
                return cache.as_ref().map(|(_, l)| l.clone()).unwrap_or_default();
            }
        };
        *cache = Some((Instant::now(), list.clone()));
        list
    }

    fn usable(&self, a: &AdapterInfo) -> bool {
        a.connected
            && a.ipv4_gateway().is_some()
            && !a.ipv4.is_empty()
            && a.if_index != self.tun_if_index.load(Ordering::Relaxed)
    }

    /// The adapter Windows would pick: the lowest-metric one that can reach the internet.
    fn default_route(&self, adapters: &[AdapterInfo]) -> Route {
        adapters
            .iter()
            .filter(|a| self.usable(a))
            .min_by_key(|a| a.ipv4_metric)
            .map_or(Route::Block, |a| Route::Interface(a.if_index))
    }
}

impl Policy for RulePolicy {
    fn route(&self, flow: &Flow) -> Route {
        if let Some(if_index) = self.force {
            return Route::Interface(if_index);
        }
        let owner = match flow.proto {
            Proto::Tcp => router_sys::processes::tcp4_owner(flow.app, flow.dst),
            Proto::Udp => router_sys::processes::udp4_owner(flow.app),
        };
        let pid = owner.ok().flatten();
        let exe = pid.and_then(router_sys::processes::exe_name);
        let adapters = self.adapters();

        let route = match exe.as_deref().and_then(|e| self.rules.get(e)) {
            Some(rule) => match adapters
                .iter()
                .find(|a| a.guid.eq_ignore_ascii_case(&rule.adapter_guid) && self.usable(a))
            {
                Some(a) => Route::Interface(a.if_index),
                None => match rule.on_unavailable {
                    Fallback::UseDefault => self.default_route(&adapters),
                    Fallback::Block => Route::Block,
                },
            },
            None => self.default_route(&adapters),
        };
        debug!(proto = ?flow.proto, dst = %flow.dst, ?pid, ?exe, ?route, "routing decision");
        route
    }
}
