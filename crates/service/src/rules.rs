//! Uygulama → adaptör kurallarının saklanması (%ProgramData%\Router\rules.json).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use anyhow::{bail, Context, Result};
use router_common::{normalize_exe, Fallback, Rule};

pub fn data_dir() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Router")
}

pub struct RuleStore {
    path: PathBuf,
    rules: RwLock<BTreeMap<String, Rule>>,
}

impl RuleStore {
    pub fn load(path: PathBuf) -> Result<Self> {
        let rules = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<Vec<Rule>>(&bytes)
                .with_context(|| format!("{} okunamadı", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("{} açılamadı", path.display())),
        };
        let rules = rules.into_iter().map(|r| (r.exe.clone(), r)).collect();
        Ok(Self { path, rules: RwLock::new(rules) })
    }

    pub fn list(&self) -> Vec<Rule> {
        self.rules.read().unwrap().values().cloned().collect()
    }

    /// `exe` küçük harfli olmalıdır ([`normalize_exe`]).
    pub fn get(&self, exe: &str) -> Option<Rule> {
        self.rules.read().unwrap().get(exe).cloned()
    }

    /// `adapter_guid: None` kuralı siler.
    pub fn set(&self, exe: &str, adapter_guid: Option<String>) -> Result<()> {
        let exe = normalize_exe(exe);
        if exe.is_empty() || exe.len() > 260 || exe.contains(['\\', '/']) {
            bail!("geçersiz uygulama adı: {exe:?}");
        }
        let mut rules = self.rules.write().unwrap();
        match adapter_guid {
            Some(guid) => {
                let on_unavailable = rules.get(&exe).map_or(Fallback::default(), |r| r.on_unavailable);
                rules.insert(exe.clone(), Rule { exe, adapter_guid: guid, on_unavailable });
            }
            None => {
                rules.remove(&exe);
            }
        }
        // Kilit tutulurken kaydedilir: eşzamanlı iki değişiklik dosyada karışmaz.
        save(&self.path, &rules.values().cloned().collect::<Vec<_>>())
    }
}

/// Önce geçici dosyaya yazar, sonra yerine taşır: elektrik kesilse bile dosya bozulmaz.
fn save(path: &Path, rules: &[Rule]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(rules)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
