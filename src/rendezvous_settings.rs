//! Settings that RDS controls without restarting hbbs. The host's sync timer writes them from
//! the RDS Config page into FILE in hbbs's working directory as `key=value` lines; hbbs re-reads
//! the file at most every 15 s. A key the file doesn't have falls back to the environment.
use hbb_common::log;
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

pub(crate) const FILE: &str = "rendezvous_settings";
const RELOAD_EVERY: Duration = Duration::from_secs(15);

struct Cache {
    values: HashMap<String, String>,
    checked: Option<Instant>,
}

/// The value of `key` (lowercase, trimmed): from FILE, else from the hbbs argument/environment
/// variable of that name. `source` says which.
pub(crate) fn get(key: &str) -> (Option<String>, &'static str) {
    static CACHE: Lazy<Mutex<Cache>> =
        Lazy::new(|| Mutex::new(Cache { values: HashMap::new(), checked: None }));
    let mut cache = CACHE.lock().unwrap();
    if cache.checked.map_or(true, |t| t.elapsed() >= RELOAD_EVERY) {
        cache.checked = Some(Instant::now());
        cache.values = match std::fs::read_to_string(FILE) {
            Ok(text) => text
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_lowercase()))
                .collect(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(err) => {
                log::warn!("{}: {}", FILE, err);
                HashMap::new()
            }
        };
    }
    if let Some(value) = cache.values.get(key) {
        return (Some(value.clone()), FILE);
    }
    drop(cache);
    let value = crate::common::get_arg(key).trim().to_lowercase();
    ((!value.is_empty()).then_some(value), "environment")
}
