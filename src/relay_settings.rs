//! Managed hardening: hbbr's settings, changed without restarting it, as rendezvous_settings is for hbbs:
//! `key=value` lines in FILE in hbbr's working directory, re-read at most every 15 s. A key the file
//! doesn't have falls back to the hbbr argument/environment variable of that name.
use hbb_common::log;
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

pub(crate) const FILE: &str = "relay_settings";
const RELOAD_EVERY: Duration = Duration::from_secs(15);

#[derive(Default)]
pub(crate) struct Cache {
    values: HashMap<String, String>,
    checked: Option<Instant>,
    /// The last read failed; logged once until one works again.
    failing: bool,
}

impl Cache {
    /// Takes in a read of FILE: its values, or none when it isn't there. A read that fails
    /// otherwise keeps the values last read, so a passing error can't turn enforce into a default.
    pub(crate) fn take_read(&mut self, read: std::io::Result<String>) {
        self.values = match read {
            Ok(text) => text
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_lowercase()))
                .collect(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(err) => {
                if !self.failing {
                    log::warn!("{}: {}; keeping the settings last read", FILE, err);
                }
                self.failing = true;
                return;
            }
        };
        self.failing = false;
    }

    pub(crate) fn value(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
}

/// The value of `key` (lowercase, trimmed): from FILE, else from the environment. `source` says
/// which.
pub(crate) fn get(key: &str) -> (Option<String>, &'static str) {
    static CACHE: Lazy<Mutex<Cache>> = Lazy::new(Default::default);
    let mut cache = CACHE.lock().unwrap();
    if cache.checked.map_or(true, |t| t.elapsed() >= RELOAD_EVERY) {
        cache.checked = Some(Instant::now());
        cache.take_read(std::fs::read_to_string(FILE));
    }
    if let Some(value) = cache.value(key) {
        return (Some(value.to_owned()), FILE);
    }
    drop(cache);
    let value = crate::common::get_arg(key).trim().to_lowercase();
    ((!value.is_empty()).then_some(value), "environment")
}
