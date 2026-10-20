// Don't open a console window behind the app in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod client;

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use router_common::{AdapterInfo, AppInfo, Request, Response, Rule};
use slint::{Model, ModelRc, SharedString, VecModel};

slint::include_modules!();

const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Adapter GUID for each ComboBox entry (0 = default).
type ChoiceGuids = Arc<Mutex<Vec<Option<String>>>>;

struct Snapshot {
    adapters: Vec<AdapterInfo>,
    apps: Vec<AppInfo>,
    rules: Vec<Rule>,
}

/// Ready-to-display data for the UI; computed on a background thread.
struct View {
    status: String,
    adapters: Vec<AdapterRow>,
    choices: Vec<SharedString>,
    choice_guids: Vec<Option<String>>,
    apps: Vec<AppRow>,
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;
    ui.set_adapters(ModelRc::new(VecModel::<AdapterRow>::default()));
    ui.set_choices(ModelRc::new(VecModel::<SharedString>::default()));
    ui.set_apps(ModelRc::new(VecModel::<AppRow>::default()));
    ui.set_status_text("Connecting to the service...".into());

    let guids: ChoiceGuids = Default::default();
    let (refresh_tx, refresh_rx) = mpsc::channel::<()>();

    let tx = refresh_tx.clone();
    ui.on_refresh(move || {
        let _ = tx.send(());
    });

    let (assign_guids, weak) = (guids.clone(), ui.as_weak());
    ui.on_assign(move |exe, index| {
        let guid = assign_guids
            .lock()
            .unwrap()
            .get(index as usize)
            .cloned()
            .flatten();
        let req = Request::SetRule {
            exe: exe.to_string(),
            adapter_guid: guid,
        };
        let (tx, weak) = (refresh_tx.clone(), weak.clone());
        std::thread::spawn(move || {
            if let Err(e) = client::request(&req) {
                let msg = format!("Rule could not be saved: {e}");
                let _ = weak.upgrade_in_event_loop(move |ui| ui.set_status_text(msg.into()));
            }
            let _ = tx.send(());
        });
    });

    // Polls the service periodically. Stops when the window closes (no senders left).
    let weak = ui.as_weak();
    std::thread::spawn(move || loop {
        let result = fetch().map(|s| build_view(&s));
        let guids = guids.clone();
        let delivered = weak.upgrade_in_event_loop(move |ui| match result {
            Ok(view) => apply(&ui, view, &guids),
            Err(e) => show_offline(&ui, &e),
        });
        if delivered.is_err() {
            break;
        }
        match refresh_rx.recv_timeout(POLL_INTERVAL) {
            Ok(()) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    });

    ui.run()
}

fn fetch() -> io::Result<Snapshot> {
    let unexpected = || io::Error::other("unexpected response from the service");
    let Response::Adapters(adapters) = client::request(&Request::ListAdapters)? else {
        return Err(unexpected());
    };
    let Response::Apps(apps) = client::request(&Request::ListApps)? else {
        return Err(unexpected());
    };
    let Response::Rules(rules) = client::request(&Request::GetRules)? else {
        return Err(unexpected());
    };
    Ok(Snapshot {
        adapters,
        apps,
        rules,
    })
}

fn build_view(s: &Snapshot) -> View {
    // Hide virtual adapters (Hyper-V, VPN, etc.); always show ones that can reach the internet.
    let usable: Vec<&AdapterInfo> = s
        .adapters
        .iter()
        .filter(|a| a.hardware || a.has_internet_route())
        .collect();

    let mut choices: Vec<SharedString> = vec!["Default (Windows decides)".into()];
    let mut choice_guids: Vec<Option<String>> = vec![None];
    for a in &usable {
        let mut label = a.display_name();
        if !a.connected {
            label.push_str(" (not connected)");
        }
        choices.push(label.into());
        choice_guids.push(Some(a.guid.clone()));
    }
    // Keep the selection if a rule points at an adapter that is not plugged in right now.
    for rule in &s.rules {
        if !choice_guids
            .iter()
            .any(|g| g.as_deref() == Some(rule.adapter_guid.as_str()))
        {
            choices.push("Adapter not plugged in".into());
            choice_guids.push(Some(rule.adapter_guid.clone()));
        }
    }

    let index_of = |guid: &str| {
        choice_guids
            .iter()
            .position(|g| g.as_deref() == Some(guid))
            .unwrap_or(0) as i32
    };
    let rule_of: HashMap<&str, &str> = s
        .rules
        .iter()
        .map(|r| (r.exe.as_str(), r.adapter_guid.as_str()))
        .collect();

    let mut apps: BTreeMap<&str, AppRow> = BTreeMap::new();
    for app in &s.apps {
        let pids: Vec<String> = app.pids.iter().map(u32::to_string).collect();
        apps.insert(
            &app.exe,
            AppRow {
                exe: app.exe.as_str().into(),
                detail: format!(
                    "{} TCP · {} UDP · PID {}",
                    app.tcp_connections,
                    app.udp_endpoints,
                    pids.join(", ")
                )
                .into(),
                choice: rule_of.get(app.exe.as_str()).map_or(0, |g| index_of(g)),
                running: true,
            },
        );
    }
    for rule in &s.rules {
        apps.entry(&rule.exe).or_insert_with(|| AppRow {
            exe: rule.exe.as_str().into(),
            detail: "Not running".into(),
            choice: index_of(&rule.adapter_guid),
            running: false,
        });
    }

    let online = usable
        .iter()
        .filter(|a| a.connected && a.has_internet_route())
        .count();
    View {
        status: format!(
            "Service running · {online} internet connection{}",
            if online == 1 { "" } else { "s" }
        ),
        adapters: usable.iter().map(|a| adapter_row(a)).collect(),
        choices,
        choice_guids,
        apps: apps.into_values().collect(),
    }
}

fn adapter_row(a: &AdapterInfo) -> AdapterRow {
    let mut parts = vec![a.description.clone()];
    if !a.connected {
        parts.push("not connected".into());
    } else if let Some(ip) = a.ipv4.first() {
        parts.push(format!("IP {ip}"));
    }
    if let Some(q) = a.signal_quality {
        parts.push(format!("Signal {q}%"));
    }
    if a.connected && a.link_speed_bps > 0 {
        parts.push(format!("{} Mbps", a.link_speed_bps / 1_000_000));
    }
    if a.connected && !a.has_internet_route() {
        parts.push("no internet".into());
    }
    AdapterRow {
        title: a.display_name().into(),
        subtitle: parts.join(" · ").into(),
        connected: a.connected,
        internet: a.connected && a.has_internet_route(),
    }
}

fn apply(ui: &MainWindow, view: View, guids: &Mutex<Vec<Option<String>>>) {
    *guids.lock().unwrap() = view.choice_guids;
    ui.set_service_online(true);
    ui.set_status_text(view.status.into());
    sync_model(&ui.get_adapters(), view.adapters);
    sync_model(&ui.get_choices(), view.choices);
    sync_model(&ui.get_apps(), view.apps);
}

fn show_offline(ui: &MainWindow, e: &io::Error) {
    ui.set_service_online(false);
    let msg = if e.kind() == io::ErrorKind::NotFound {
        "Service not running".to_string()
    } else {
        format!("Service error: {e}")
    };
    ui.set_status_text(msg.into());
    sync_model(&ui.get_adapters(), Vec::new());
    sync_model(&ui.get_apps(), Vec::new());
}

/// Updates only the rows that changed, so the list isn't redrawn on every refresh
/// and a dropdown the user has open stays open.
fn sync_model<T: Clone + PartialEq + 'static>(model: &ModelRc<T>, rows: Vec<T>) {
    let Some(vec) = model.as_any().downcast_ref::<VecModel<T>>() else {
        return;
    };
    if vec.row_count() != rows.len() {
        vec.set_vec(rows);
        return;
    }
    for (i, row) in rows.into_iter().enumerate() {
        if vec.row_data(i).as_ref() != Some(&row) {
            vec.set_row_data(i, row);
        }
    }
}
