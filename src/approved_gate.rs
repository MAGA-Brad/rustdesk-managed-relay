//! Approved-device gate: only devices approved in the RDS directory may start a connection.
//!
//! hbbs is never told who is asking - PunchHoleRequest and RequestRelay carry only the target id -
//! so a request is attributed by its source address: it must come from the IP an approved device
//! registered from within REG_TIMEOUT. The approved ids are synced from the RDS database into
//! APPROVED_IDS_FILE (one id per line) by a host timer.
//!
//! APPROVED_GATE: off (default), log (allow, but log what would be blocked), enforce.
//! A missing, empty or stale id list fails open with a warning instead of locking every device
//! out; the controlled client's own check is the strict layer.
use hbb_common::log;
use once_cell::sync::Lazy;
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    Off,
    Log,
    Enforce,
}

const RELOAD_EVERY: Duration = Duration::from_secs(15);
const STALE_AFTER: Duration = Duration::from_secs(600);
const WARN_EVERY: Duration = Duration::from_secs(300);

pub(crate) fn mode() -> Mode {
    static MODE: Lazy<Mode> = Lazy::new(|| {
        let mode = match crate::common::get_arg("approved-gate").to_lowercase().as_str() {
            "log" => Mode::Log,
            "enforce" => Mode::Enforce,
            _ => Mode::Off,
        };
        log::info!("approved-gate mode: {:?} (ids file {})", mode, ids_file());
        mode
    });
    *MODE
}

fn ids_file() -> String {
    let path = crate::common::get_arg("approved-ids-file");
    if path.is_empty() {
        "approved_ids".to_owned()
    } else {
        path
    }
}

#[derive(Default)]
struct Cache {
    checked: Option<Instant>,
    modified: Option<SystemTime>,
    ids: Option<Arc<HashSet<String>>>,
    warned: Option<Instant>,
}

static CACHE: Lazy<Mutex<Cache>> = Lazy::new(Default::default);

/// The approved ids, or None while the list is missing, empty or stale (callers then fail open).
pub(crate) fn approved_ids() -> Option<Arc<HashSet<String>>> {
    let mut cache = CACHE.lock().unwrap();
    if cache.checked.map_or(true, |t| t.elapsed() >= RELOAD_EVERY) {
        cache.checked = Some(Instant::now());
        reload(&mut cache);
    }
    let stale = cache.modified.map_or(true, |m| {
        m.elapsed().map_or(false, |age| age > STALE_AFTER)
    });
    if cache.ids.is_some() && !stale {
        return cache.ids.clone();
    }
    if cache.warned.map_or(true, |t| t.elapsed() >= WARN_EVERY) {
        cache.warned = Some(Instant::now());
        log::warn!(
            "approved-gate: approved id list {} is missing, empty or older than {}s - allowing all requests",
            ids_file(),
            STALE_AFTER.as_secs()
        );
    }
    None
}

fn reload(cache: &mut Cache) {
    let path = ids_file();
    let modified = match std::fs::metadata(&path).and_then(|m| m.modified()) {
        Ok(modified) => modified,
        Err(_) => {
            cache.ids = None;
            cache.modified = None;
            return;
        }
    };
    if cache.modified == Some(modified) {
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let ids: HashSet<String> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_owned)
                .collect();
            log::info!("approved-gate: loaded {} approved ids", ids.len());
            cache.ids = (!ids.is_empty()).then(|| Arc::new(ids));
            cache.modified = Some(modified);
        }
        Err(err) => {
            log::warn!("approved-gate: failed to read {}: {}", path, err);
            cache.ids = None;
            cache.modified = None;
        }
    }
}
