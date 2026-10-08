//! Device passports on hbbs connections.
//!
//! Right after the key exchange a managed device (build 34+) sends DeviceAuth: its passport,
//! issued by the CA VM, and its identity key's signature over this connection's key exchange, so
//! the proof fits this one connection and nothing recorded can be replayed elsewhere. hbbs checks
//! the passport against the CA roots it was started with (PASSPORT_ROOTS: never from RDS, so the
//! RDS database can't swap the CA), that the device is approved, and that the passport's identity
//! key is the one RDS lists for that id (APPROVED_KEYS_FILE, `id fingerprint` per line: the
//! two-box rule, so neither the CA nor RDS alone can make a device). The connection then belongs
//! to that device.
//!
//! What hbbs does with it is the mode (`passport=` in rendezvous_settings, from RDS Config):
//! off (not offered), log (count, refuse nothing), test (refuse only where a device listed in
//! `passport-test-ids` is involved), enforce (refuse every request the connection can't back).
//! Counts go to the log and to STATS_FILE every 5 minutes.
use crate::rendezvous_kx::Binding;
use hbb_common::{log, rendezvous_proto::DeviceAuth};
use once_cell::sync::Lazy;
use rdc_passport::{Error as PassportError, Window};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

/// Domain of the device's signature over the key exchange (the client signs the same bytes).
pub(crate) const DOMAIN: &[u8] = b"rdcp1-devauth\0";
const CLOCK_SKEW_SECS: i64 = 600;
const DEFAULT_GRACE_DAYS: i64 = 7;
const MAX_GRACE_DAYS: i64 = 30;
const STATS_FILE: &str = "passport_stats";
const REPORT_EVERY: Duration = Duration::from_secs(300);
const RELOAD_EVERY: Duration = Duration::from_secs(15);
const KEYS_STALE_AFTER: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    Off,
    Log,
    Test,
    Enforce,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Log => "log",
            Mode::Test => "test",
            Mode::Enforce => "enforce",
        }
    }
}

/// The mode now (see rendezvous_settings); changes are logged.
pub(crate) fn mode() -> Mode {
    static LAST: Lazy<Mutex<Option<Mode>>> = Lazy::new(|| Mutex::new(None));
    let (value, source) = crate::rendezvous_settings::get("passport");
    let mode = match value.as_deref() {
        Some("log") => Mode::Log,
        Some("test") => Mode::Test,
        Some("enforce") => Mode::Enforce,
        _ => Mode::Off,
    };
    let mut last = LAST.lock().unwrap();
    if *last != Some(mode) {
        log::info!(
            "passport mode: {:?} (from {}), {} CA root(s)",
            mode,
            source,
            roots().len()
        );
        *last = Some(mode);
    }
    mode
}

/// Whether hbbs asks for DeviceAuth in its key exchange parameters.
pub(crate) fn offered() -> bool {
    mode() != Mode::Off && !roots().is_empty()
}

/// CA root public keys from PASSPORT_ROOTS (base64url, comma-separated), read once.
fn roots() -> &'static [ed25519_dalek::VerifyingKey] {
    static ROOTS: Lazy<Vec<ed25519_dalek::VerifyingKey>> = Lazy::new(|| {
        let keys: Vec<_> = crate::common::get_arg("passport-roots")
            .split(',')
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .filter_map(|k| match rdc_passport::parse_public_key(k) {
                Ok(key) => Some(key),
                Err(err) => {
                    log::error!("passport: ignoring unusable CA root {:?}: {}", k, err);
                    None
                }
            })
            .collect();
        if keys.is_empty() {
            log::warn!("passport: no CA roots (PASSPORT_ROOTS); DeviceAuth is not offered");
        }
        keys
    });
    &ROOTS
}

fn grace_secs() -> i64 {
    let (value, _) = crate::rendezvous_settings::get("passport-grace-days");
    value
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(DEFAULT_GRACE_DAYS)
        .clamp(0, MAX_GRACE_DAYS)
        * 86400
}

fn test_ids() -> HashSet<String> {
    let (value, _) = crate::rendezvous_settings::get("passport-test-ids");
    value
        .unwrap_or_default()
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The device a connection proved itself to be.
pub(crate) struct Device {
    pub id: String,
    pub serial: String,
    pub in_grace: bool,
}

/// Per connection: its key exchange and, once DeviceAuth checked out, the device.
#[derive(Default)]
pub(crate) struct ConnAuth {
    pub binding: Option<Binding>,
    pub device: Option<Device>,
    pub failure: Option<&'static str>,
}

/// Checks a DeviceAuth on `conn`; `server_pk` is hbbs's signing public key (the one clients pin).
pub(crate) fn authenticate(conn: &mut ConnAuth, msg: &DeviceAuth, server_pk: &[u8], addr: SocketAddr) {
    if mode() == Mode::Off {
        return;
    }
    match check(conn.binding.as_ref(), msg, server_pk) {
        Ok(device) => {
            STATS.lock().unwrap().auth_ok += 1;
            if device.in_grace {
                STATS.lock().unwrap().auth_grace += 1;
            }
            log::debug!(
                "passport: {:?} is {} (serial {}{})",
                addr,
                device.id,
                &device.serial[..device.serial.len().min(12)],
                if device.in_grace { ", in grace" } else { "" }
            );
            conn.failure = None;
            conn.device = Some(device);
        }
        Err((reason, rid)) => {
            *STATS.lock().unwrap().auth_failed.entry(reason).or_default() += 1;
            log::info!("passport: DeviceAuth from {:?} (id {:?}) rejected: {}", addr, rid, reason);
            conn.failure = Some(reason);
            conn.device = None;
        }
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The signed bytes: domain, hbbs's key, both ephemeral keys of the exchange, the picked version.
pub(crate) fn signed_message(server_pk: &[u8], binding: &Binding) -> Vec<u8> {
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(server_pk);
    message.extend_from_slice(&binding.initiator_pk);
    message.extend_from_slice(&binding.responder_pk);
    message.extend_from_slice(&binding.version.to_le_bytes());
    message
}

type Failure = (&'static str, String);

fn check(binding: Option<&Binding>, msg: &DeviceAuth, server_pk: &[u8]) -> Result<Device, Failure> {
    let fail = |reason: &'static str| (reason, String::new());
    let binding = binding.ok_or_else(|| fail("no key exchange on this connection"))?;
    let window = Window {
        now: now_secs(),
        skew: CLOCK_SKEW_SECS,
        grace: grace_secs(),
    };
    let verified = rdc_passport::verify(&msg.passport, roots(), window).map_err(|e| fail(reason(&e)))?;
    let passport = verified.passport;
    let rid = passport.rid.clone();
    let fail = |reason: &'static str| (reason, rid.clone());
    if !passport.scopes.iter().any(|s| s == "hbbs") {
        return Err(fail("passport not valid for hbbs"));
    }
    if passport.idk_alg != "ed25519" {
        return Err(fail("unsupported identity key"));
    }
    match crate::approved_gate::approved_ids() {
        Some(ids) if !ids.contains(&rid) => return Err(fail("device not approved")),
        Some(_) => {}
        None if verified.in_grace => return Err(fail("grace needs the approved list")),
        None => {}
    }
    let raw_key = rdc_passport::unb64(&passport.idk).map_err(|_| fail("malformed identity key"))?;
    match approved_key(&rid) {
        KeyOnFile::Matches(fp) if fp == rdc_passport::fingerprint(&raw_key) => {}
        KeyOnFile::Matches(_) => return Err(fail("identity key differs from RDS")),
        KeyOnFile::NoEntry => return Err(fail("no identity key on file at RDS")),
        KeyOnFile::Unavailable => return Err(fail("RDS key list unavailable")),
    }
    let key = rdc_passport::parse_public_key(&passport.idk).map_err(|_| fail("malformed identity key"))?;
    let signature: [u8; 64] = msg.signature[..]
        .try_into()
        .map_err(|_| fail("malformed signature"))?;
    key.verify_strict(
        &signed_message(server_pk, binding),
        &ed25519_dalek::Signature::from_bytes(&signature),
    )
    .map_err(|_| fail("signature does not match this connection"))?;
    Ok(Device {
        id: rid,
        serial: passport.serial,
        in_grace: verified.in_grace,
    })
}

fn reason(err: &PassportError) -> &'static str {
    match err {
        PassportError::Malformed(_) => "malformed passport",
        PassportError::UntrustedRoot | PassportError::BadIkcSignature => "not issued by a trusted CA",
        PassportError::IkcNotYetValid | PassportError::IkcExpired => "issuing key outside its validity",
        PassportError::BadSignature => "bad passport signature",
        PassportError::NotYetValid => "passport not yet valid",
        PassportError::Expired => "passport expired",
        PassportError::WrongIssuer => "passport from another issuing key",
        PassportError::Unsupported(_) => "unsupported passport",
        PassportError::StaleRequest => "stale",
    }
}

/// What a request on a connection is, for the check and the counts.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Kind {
    /// A controller asking for a connection to `target` (PunchHoleRequest, RequestRelay).
    Request,
    /// A controlled device answering for itself (PunchHoleSent, LocalAddr, RelayResponse).
    Reply,
    /// A device asking which of its peers are online, as itself.
    Online,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Request => "request",
            Kind::Reply => "reply",
            Kind::Online => "online",
        }
    }
}

/// Whether the request may go ahead. `own_id` is the id the message speaks for (replies, online
/// requests), `target` the device a controller wants (requests).
pub(crate) fn allows(conn: &ConnAuth, kind: Kind, own_id: &str, target: &str, addr: SocketAddr) -> bool {
    let mode = mode();
    if mode == Mode::Off {
        return true;
    }
    let proven = match (&conn.device, kind) {
        (Some(_), Kind::Request) => true,
        // A RelayResponse that only carries a WebRTC answer has no id: it speaks for the
        // connection's own (proven) device.
        (Some(_), Kind::Reply) if own_id.is_empty() => true,
        (Some(device), _) => device.id == own_id,
        (None, _) => false,
    };
    let applies = match mode {
        Mode::Enforce => true,
        Mode::Test => {
            let ids = test_ids();
            (!target.is_empty() && ids.contains(target)) || (!own_id.is_empty() && ids.contains(own_id))
        }
        _ => false,
    };
    let refuse = !proven && applies;
    {
        let mut stats = STATS.lock().unwrap();
        let counts = stats.requests.entry(kind).or_default();
        match (proven, refuse) {
            (true, _) => counts.proven += 1,
            (false, true) => counts.refused += 1,
            (false, false) => counts.unproven += 1,
        }
    }
    if refuse {
        log::info!(
            "passport: refused {} from {:?} (as {:?}, for {:?}): {}",
            kind.as_str(),
            addr,
            conn.device.as_ref().map(|d| d.id.as_str()).unwrap_or(own_id),
            target,
            conn.failure.unwrap_or(if conn.device.is_some() { "proven as another id" } else { "no passport" })
        );
    }
    !refuse
}

// --- the two-box key list -------------------------------------------------------------------

enum KeyOnFile {
    Matches(String),
    NoEntry,
    Unavailable,
}

#[derive(Default)]
struct KeysCache {
    checked: Option<Instant>,
    modified: Option<SystemTime>,
    keys: Option<Arc<HashMap<String, String>>>,
    warned: Option<Instant>,
}

fn keys_file() -> String {
    let path = crate::common::get_arg("approved-keys-file");
    if path.is_empty() {
        "approved_keys".to_owned()
    } else {
        path
    }
}

/// The fingerprint RDS lists for `id`. A list that stops updating is kept (with a warning) rather
/// than dropped, so a broken sync doesn't lock every device out; a list never read is unavailable.
fn approved_key(id: &str) -> KeyOnFile {
    static CACHE: Lazy<Mutex<KeysCache>> = Lazy::new(Default::default);
    let mut cache = CACHE.lock().unwrap();
    if cache.checked.map_or(true, |t| t.elapsed() >= RELOAD_EVERY) {
        cache.checked = Some(Instant::now());
        reload_keys(&mut cache);
    }
    let stale = cache
        .modified
        .map_or(false, |m| m.elapsed().map_or(false, |age| age > KEYS_STALE_AFTER));
    if stale && cache.warned.map_or(true, |t| t.elapsed() >= REPORT_EVERY) {
        cache.warned = Some(Instant::now());
        log::warn!("passport: {} has not been updated for over {}s", keys_file(), KEYS_STALE_AFTER.as_secs());
    }
    match &cache.keys {
        None => KeyOnFile::Unavailable,
        Some(keys) => keys
            .get(id)
            .map_or(KeyOnFile::NoEntry, |fp| KeyOnFile::Matches(fp.clone())),
    }
}

fn reload_keys(cache: &mut KeysCache) {
    let path = keys_file();
    let Ok(modified) = std::fs::metadata(&path).and_then(|m| m.modified()) else {
        return;
    };
    if cache.modified == Some(modified) {
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let keys: HashMap<String, String> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .filter_map(|l| {
                    let mut parts = l.split_whitespace();
                    Some((parts.next()?.to_owned(), parts.next()?.to_lowercase()))
                })
                .collect();
            log::info!("passport: loaded {} identity key fingerprints", keys.len());
            cache.keys = Some(Arc::new(keys));
            cache.modified = Some(modified);
        }
        Err(err) => log::warn!("passport: failed to read {}: {}", path, err),
    }
}

// --- counts for RDS -------------------------------------------------------------------------

#[derive(Default)]
struct RequestCounts {
    proven: u64,
    unproven: u64,
    refused: u64,
}

#[derive(Default)]
struct Stats {
    auth_ok: u64,
    auth_grace: u64,
    auth_failed: HashMap<&'static str, u64>,
    requests: HashMap<Kind, RequestCounts>,
}

static STATS: Lazy<Mutex<Stats>> = Lazy::new(Default::default);

/// Every 5 minutes, logs the counts and writes them to STATS_FILE (JSON, replaced atomically).
pub(crate) fn spawn_report() {
    mode();
    hbb_common::tokio::spawn(async {
        let mut every = hbb_common::tokio::time::interval(REPORT_EVERY);
        every.tick().await;
        loop {
            every.tick().await;
            let stats = std::mem::take(&mut *STATS.lock().unwrap());
            let mode = mode();
            let failed: serde_json::Map<String, serde_json::Value> = stats
                .auth_failed
                .iter()
                .map(|(reason, n)| ((*reason).to_owned(), (*n).into()))
                .collect();
            let requests: serde_json::Map<String, serde_json::Value> = [Kind::Request, Kind::Reply, Kind::Online]
                .iter()
                .map(|kind| {
                    let c = stats.requests.get(kind);
                    (
                        kind.as_str().to_owned(),
                        serde_json::json!({
                            "proven": c.map_or(0, |c| c.proven),
                            "unproven": c.map_or(0, |c| c.unproven),
                            "refused": c.map_or(0, |c| c.refused),
                        }),
                    )
                })
                .collect();
            let json = serde_json::json!({
                "at": now_secs(),
                "window_seconds": REPORT_EVERY.as_secs(),
                "mode": mode.as_str(),
                "roots": roots().len(),
                "auth_ok": stats.auth_ok,
                "auth_grace": stats.auth_grace,
                "auth_failed": failed,
                "requests": requests,
            });
            if mode != Mode::Off {
                log::info!("passport, last 5 min: {}", json);
            }
            let tmp = format!("{STATS_FILE}.tmp");
            if let Err(err) = std::fs::write(&tmp, format!("{json}\n")).and_then(|_| std::fs::rename(&tmp, STATS_FILE)) {
                log::warn!("passport: could not write {}: {}", STATS_FILE, err);
            }
        }
    });
}
