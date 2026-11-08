//! Managed hardening (HBB-02): relay tickets. hbbr pairs the two connections that present the same uuid;
//! before tickets, any two did. hbbs now mints a ticket for each side of a relay it sets up, and
//! hbbr checks each side's on its own (relay_server.rs, `ticket_mode` in relay_settings).
//!
//! A ticket is `rt1.<side>.<expiry>.<controller id>.<controlled id>.<tag>`: side `c` (the
//! controller's) or `t` (the controlled side's), expiry in unix seconds, ids and tag base64url
//! without padding (an id hbbs doesn't know is empty). The tag is HMAC-SHA256 over DOMAIN, the side,
//! the expiry and the length-prefixed uuid and ids, under a key only hbbs and hbbr hold.
//!
//! The key is 32 random bytes, base64, in the file RELAY_TICKET_KEY_FILE names (default
//! `relay_ticket.key` in the working directory). hbbs reads it at startup and makes it (mode 0600,
//! written whole to a temporary file, then renamed into place) when it is missing, empty or cut
//! short; hbbr only reads it. Both look at the file's modification time every 15 s and read it
//! again when it changed; for GRACE after a change, hbbr still accepts tickets under the key before.
//!
//! hbbs mints and hbbr verifies, so each binary leaves half of this unused.
#![allow(dead_code)]
use hbb_common::log;
use once_cell::sync::Lazy;
use sodiumoxide::crypto::auth::hmacsha256::{self, Key, Tag};
use std::{
    sync::Mutex,
    time::{Duration, Instant, SystemTime},
};

const VERSION: &str = "rt1";
const DOMAIN: &[u8] = b"rdc-relay-ticket-v1\0";
/// How long a ticket is good for after hbbs mints it.
pub(crate) const TTL_SECS: u64 = 120;
const DEFAULT_KEY_FILE: &str = "relay_ticket.key";
/// Client uuids are 36 characters; anything longer gets no ticket.
pub(crate) const MAX_UUID: usize = 128;
/// Longer ids (hbbs takes up to 253 bytes) are left out of a ticket rather than bloat it.
pub(crate) const MAX_ID: usize = 255;
const MAX_TICKET: usize = 2048;
const RELOAD_EVERY: Duration = Duration::from_secs(15);
/// After the key file changes, tickets under the key before still verify this long: hbbs and hbbr
/// each notice the change within RELOAD_EVERY, and a ticket minted before it lives TTL_SECS.
const GRACE: Duration = Duration::from_secs(600);
/// Base64 of a 32-byte key, the shortest text hbbs writes: a shorter file is a write that didn't
/// finish (or a raw key).
const KEY_TEXT_LEN: usize = 44;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Role {
    Controller,
    Controlled,
}

impl Role {
    fn code(self) -> &'static str {
        match self {
            Role::Controller => "c",
            Role::Controlled => "t",
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Role::Controller => "controller",
            Role::Controlled => "controlled",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Ticket {
    pub role: Role,
    pub expiry: u64,
    /// The relay it was minted for (the one it verified against).
    pub uuid: String,
    pub controller_id: String,
    pub controlled_id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Check {
    Valid(Ticket),
    Missing,
    Bad(&'static str),
    Expired(Ticket),
}

impl Check {
    pub(crate) fn outcome(&self) -> &'static str {
        match self {
            Check::Valid(_) => "valid",
            Check::Missing => "missing",
            Check::Bad(_) => "bad",
            Check::Expired(_) => "expired",
        }
    }
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn b64(bytes: &[u8]) -> String {
    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}

fn signed(role: Role, expiry: u64, uuid: &str, controller_id: &str, controlled_id: &str) -> Vec<u8> {
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(role.code().as_bytes());
    message.extend_from_slice(&expiry.to_be_bytes());
    for field in [uuid, controller_id, controlled_id] {
        message.extend_from_slice(&(field.len() as u32).to_be_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    message
}

/// The ticket for `role` on the relay `uuid`, good for TTL_SECS from `now`.
pub(crate) fn mint(
    key: &Key,
    role: Role,
    uuid: &str,
    controller_id: &str,
    controlled_id: &str,
    now: u64,
) -> String {
    let expiry = now.saturating_add(TTL_SECS);
    let tag = hmacsha256::authenticate(&signed(role, expiry, uuid, controller_id, controlled_id), key);
    format!(
        "{VERSION}.{}.{expiry}.{}.{}.{}",
        role.code(),
        b64(controller_id.as_bytes()),
        b64(controlled_id.as_bytes()),
        b64(tag.as_ref())
    )
}

fn decode_id(s: &str) -> Option<String> {
    let bytes = base64::decode_config(s, base64::URL_SAFE_NO_PAD).ok()?;
    String::from_utf8(bytes).ok()
}

/// What `ticket` says for a connection to the relay `uuid`. A ticket minted for another uuid, or
/// under another key, is bad; one past its expiry, expired.
pub(crate) fn verify(key: Option<&Key>, uuid: &str, ticket: &str, now: u64) -> Check {
    verify_any(key.map(std::slice::from_ref).unwrap_or_default(), uuid, ticket, now)
}

/// verify, with a ticket good under any of `keys` (hbbr's key and, for GRACE after it changed,
/// the one before: verifying_keys).
pub(crate) fn verify_any(keys: &[Key], uuid: &str, ticket: &str, now: u64) -> Check {
    if ticket.is_empty() {
        return Check::Missing;
    }
    if keys.is_empty() {
        return Check::Bad("hbbr has no ticket key");
    }
    if uuid.is_empty() {
        return Check::Bad("no uuid");
    }
    if ticket.len() > MAX_TICKET {
        return Check::Bad("too long");
    }
    let parts: Vec<&str> = ticket.split('.').collect();
    let &[version, role, expiry, controller_id, controlled_id, tag] = parts.as_slice() else {
        return Check::Bad("malformed");
    };
    if version != VERSION {
        return Check::Bad("unknown version");
    }
    let role = match role {
        "c" => Role::Controller,
        "t" => Role::Controlled,
        _ => return Check::Bad("malformed"),
    };
    let Ok(expiry) = expiry.parse::<u64>() else {
        return Check::Bad("malformed");
    };
    let (Some(controller_id), Some(controlled_id)) = (decode_id(controller_id), decode_id(controlled_id))
    else {
        return Check::Bad("malformed");
    };
    let Some(tag) = base64::decode_config(tag, base64::URL_SAFE_NO_PAD)
        .ok()
        .and_then(|t| Tag::from_slice(&t))
    else {
        return Check::Bad("malformed");
    };
    let message = signed(role, expiry, uuid, &controller_id, &controlled_id);
    if !keys.iter().any(|key| hmacsha256::verify(&tag, &message, key)) {
        return Check::Bad("not minted for this uuid with this key");
    }
    let ticket = Ticket {
        role,
        expiry,
        uuid: uuid.to_owned(),
        controller_id,
        controlled_id,
    };
    if now > expiry {
        Check::Expired(ticket)
    } else {
        Check::Valid(ticket)
    }
}

fn key_file() -> String {
    let path = crate::common::get_arg("relay-ticket-key-file");
    if path.trim().is_empty() {
        DEFAULT_KEY_FILE.to_owned()
    } else {
        path.trim().to_owned()
    }
}

/// Why the key file can't be used.
#[derive(Debug, PartialEq)]
enum KeyError {
    /// Empty, or shorter than any key: a write that didn't finish.
    Short,
    Unusable(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            KeyError::Short => f.write_str("empty or cut short"),
            KeyError::Unusable(why) => f.write_str(why),
        }
    }
}

/// The key in `path`: base64 text (what hbbs writes) or the 32 raw bytes. Ok(None) when the file
/// isn't there.
fn read_key(path: &str) -> Result<Option<Key>, KeyError> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(KeyError::Unusable(err.to_string())),
    };
    warn_if_readable_by_others(path);
    let decoded = std::str::from_utf8(&raw)
        .ok()
        .and_then(|text| base64::decode(text.trim()).ok())
        .filter(|bytes| bytes.len() == hmacsha256::KEYBYTES);
    let bytes = decoded
        .as_deref()
        .or_else(|| (raw.len() == hmacsha256::KEYBYTES).then_some(&raw[..]));
    let text_len = std::str::from_utf8(&raw).map_or(raw.len(), |text| text.trim().len());
    match bytes.and_then(Key::from_slice) {
        Some(key) => Ok(Some(key)),
        None if text_len < KEY_TEXT_LEN => Err(KeyError::Short),
        None => Err(KeyError::Unusable("not a 32-byte key".to_owned())),
    }
}

#[cfg(unix)]
fn warn_if_readable_by_others(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.permissions().mode() & 0o077 != 0 {
            log::warn!("relay tickets: {} is readable by others; it should be mode 0600", path);
        }
    }
}

#[cfg(not(unix))]
fn warn_if_readable_by_others(_path: &str) {}

/// A new random key in `path` (mode 0600), written whole to a temporary file that then takes its
/// place, so `path` never holds part of a key. `replace`: over the (empty or cut-short) file
/// there; else a file that appeared meanwhile is read instead.
fn create_key(path: &str, replace: bool) -> Result<Key, KeyError> {
    use std::io::Write;
    let _ = sodiumoxide::init();
    let key = hmacsha256::gen_key();
    let temp = format!("{}.{}.tmp", path, std::process::id());
    let _ = std::fs::remove_file(&temp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let placed = options
        .open(&temp)
        .and_then(|mut file| {
            file.write_all(format!("{}\n", base64::encode(key.as_ref())).as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| {
            if replace {
                return std::fs::rename(&temp, path);
            }
            // A hard link never replaces a file; a filesystem without them gets the rename.
            match std::fs::hard_link(&temp, path) {
                Err(err) if err.kind() != std::io::ErrorKind::AlreadyExists => {
                    std::fs::rename(&temp, path)
                }
                linked => linked,
            }
        });
    let _ = std::fs::remove_file(&temp);
    match placed {
        Ok(()) => Ok(key),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            read_key(path)?.ok_or_else(|| KeyError::Unusable("the file vanished".to_owned()))
        }
        Err(err) => Err(KeyError::Unusable(err.to_string())),
    }
}

fn modified(path: &str) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|meta| meta.modified()).ok()
}

/// The key file as last looked at; hbbs and hbbr each keep one.
struct KeyFile {
    path: String,
    /// hbbs: while there's no key, make one when the file is missing, empty or cut short.
    make: bool,
    key: Option<Key>,
    /// The key before the last change, and when it changed.
    previous: Option<(Key, Instant)>,
    /// The file's modification time when it was last read.
    modified: Option<SystemTime>,
    checked: Option<Instant>,
    /// The last complaint logged, so each is logged once while it lasts.
    complaint: Option<String>,
}

impl KeyFile {
    fn new(path: String, make: bool) -> Self {
        KeyFile {
            path,
            make,
            key: None,
            previous: None,
            modified: None,
            checked: None,
            complaint: None,
        }
    }

    /// Looks at the file at most every RELOAD_EVERY and reads it again when its modification time
    /// changed (every time while there's no key). A file that can't be read leaves the key as it
    /// was.
    fn refresh(&mut self, now: Instant) {
        if self.checked.map_or(false, |t| now.saturating_duration_since(t) < RELOAD_EVERY) {
            return;
        }
        self.checked = Some(now);
        let modified = modified(&self.path);
        if self.key.is_some() && modified.is_some() && modified == self.modified {
            return;
        }
        self.modified = modified;
        let make = self.make && self.key.is_none();
        let (read, made) = match read_key(&self.path) {
            Ok(None) if make => (create_key(&self.path, false).map(Some), true),
            Err(KeyError::Short) if make => (create_key(&self.path, true).map(Some), true),
            read => (read, false),
        };
        match read {
            Ok(Some(key)) => {
                if made {
                    self.modified = self::modified(&self.path);
                }
                self.complaint = None;
                match self.key.replace(key.clone()) {
                    Some(old) if old != key => {
                        log::info!(
                            "relay tickets: the key in {} changed; tickets under the one before verify for {} more minutes",
                            self.path,
                            GRACE.as_secs() / 60
                        );
                        self.previous = Some((old, now));
                    }
                    Some(_) => {}
                    None if made => log::info!("relay tickets: made a new key in {}", self.path),
                    None => log::info!("relay tickets: key from {}", self.path),
                }
            }
            Ok(None) => self.complain(format!("no key at {}", self.path)),
            Err(err) => self.complain(format!("can't use the key file {}: {}", self.path, err)),
        }
    }

    /// Logs `what`, with what it means, unless it's the complaint logged last.
    fn complain(&mut self, what: String) {
        if self.complaint.as_ref() == Some(&what) {
            return;
        }
        match (&self.key, self.make) {
            (Some(_), _) => log::warn!("relay tickets: {}; still using the key read before", what),
            (None, true) => log::error!("relay tickets: {}; relays get no tickets", what),
            (None, false) => log::warn!(
                "relay tickets: {} (hbbs makes it); tickets can't be checked until it's usable",
                what
            ),
        }
        self.complaint = Some(what);
    }

    /// The keys a ticket may be under at `now`: the key, and for GRACE after it changed the one
    /// before.
    fn keys(&self, now: Instant) -> Vec<Key> {
        let previous = self
            .previous
            .as_ref()
            .filter(|(_, at)| now.saturating_duration_since(*at) < GRACE)
            .map(|(key, _)| key);
        self.key.iter().chain(previous).cloned().collect()
    }
}

/// hbbs: the key tickets are minted with: read (or made) the first time it's asked for, at
/// startup, and read again when the file changes (KeyFile). None runs hbbs without tickets.
pub(crate) fn minting_key() -> Option<Key> {
    static FILE: Lazy<Mutex<KeyFile>> = Lazy::new(|| Mutex::new(KeyFile::new(key_file(), true)));
    let mut file = FILE.lock().unwrap();
    file.refresh(Instant::now());
    file.key.clone()
}

/// hbbs: the ticket for `role` on the relay `uuid`, or "" when hbbs has no key or the uuid can't
/// have one. Ids too long for a ticket are left out.
pub(crate) fn mint_now(role: Role, uuid: &str, controller_id: &str, controlled_id: &str) -> String {
    let controller_id = if controller_id.len() <= MAX_ID { controller_id } else { "" };
    let controlled_id = if controlled_id.len() <= MAX_ID { controlled_id } else { "" };
    match minting_key() {
        Some(key) if !uuid.is_empty() && uuid.len() <= MAX_UUID => {
            mint(&key, role, uuid, controller_id, controlled_id, now_secs())
        }
        _ => String::new(),
    }
}

/// hbbr: the keys a ticket may be under, from the file hbbs makes (KeyFile): its key and, for GRACE
/// after it changed, the one before. Empty while hbbr has none.
pub(crate) fn verifying_keys() -> Vec<Key> {
    static FILE: Lazy<Mutex<KeyFile>> = Lazy::new(|| Mutex::new(KeyFile::new(key_file(), false)));
    let mut file = FILE.lock().unwrap();
    let now = Instant::now();
    file.refresh(now);
    file.keys(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
    const NOW: u64 = 1_800_000_000;

    fn key() -> Key {
        Key::from_slice(&[7u8; 32]).unwrap()
    }

    #[test]
    fn a_minted_ticket_verifies_for_its_uuid() {
        let key = key();
        for role in [Role::Controller, Role::Controlled] {
            let ticket = mint(&key, role, UUID, "123456789", "987654321", NOW);
            assert!(ticket.starts_with("rt1."));
            assert_eq!(
                verify(Some(&key), UUID, &ticket, NOW + 5),
                Check::Valid(Ticket {
                    role,
                    expiry: NOW + TTL_SECS,
                    uuid: UUID.into(),
                    controller_id: "123456789".into(),
                    controlled_id: "987654321".into(),
                })
            );
        }
    }

    #[test]
    fn unknown_ids_and_awkward_ids_round_trip() {
        let key = key();
        let longest = "x".repeat(MAX_ID);
        for (c, t) in [("", ""), ("", "abc"), ("a.b.c", "id with spaces"), ("ünï", longest.as_str())] {
            let ticket = mint(&key, Role::Controlled, UUID, c, t, NOW);
            match verify(Some(&key), UUID, &ticket, NOW) {
                Check::Valid(v) => {
                    assert_eq!(v.controller_id, c);
                    assert_eq!(v.controlled_id, t);
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn another_uuid_or_key_is_bad() {
        let key = key();
        let ticket = mint(&key, Role::Controller, UUID, "1", "2", NOW);
        assert!(matches!(
            verify(Some(&key), "11111111-2222-3333-4444-555555555555", &ticket, NOW),
            Check::Bad(_)
        ));
        let other = Key::from_slice(&[8u8; 32]).unwrap();
        assert!(matches!(verify(Some(&other), UUID, &ticket, NOW), Check::Bad(_)));
        assert!(matches!(verify(None, UUID, &ticket, NOW), Check::Bad(_)));
    }

    #[test]
    fn any_edit_is_bad() {
        let key = key();
        let ticket = mint(&key, Role::Controller, UUID, "1", "2", NOW);
        let parts: Vec<&str> = ticket.split('.').collect();
        let edits = [
            format!("rt1.t.{}.{}.{}.{}", parts[2], parts[3], parts[4], parts[5]),
            format!("rt1.c.{}.{}.{}.{}", NOW + 10_000, parts[3], parts[4], parts[5]),
            format!("rt1.c.{}.{}.{}.{}", parts[2], b64(b"9"), parts[4], parts[5]),
            format!("rt1.c.{}.{}.{}.{}", parts[2], parts[3], b64(b"9"), parts[5]),
            format!("rt1.c.{}.{}.{}.{}", parts[2], parts[4], parts[3], parts[5]),
            format!("rt1.c.{}.{}.{}.{}", parts[2], parts[3], parts[4], b64(&[0u8; 32])),
            format!("rt2.c.{}.{}.{}.{}", parts[2], parts[3], parts[4], parts[5]),
        ];
        for edited in edits {
            assert!(matches!(verify(Some(&key), UUID, &edited, NOW), Check::Bad(_)), "{edited}");
        }
    }

    #[test]
    fn past_its_expiry_is_expired() {
        let key = key();
        let ticket = mint(&key, Role::Controlled, UUID, "1", "2", NOW);
        assert!(matches!(verify(Some(&key), UUID, &ticket, NOW + TTL_SECS), Check::Valid(_)));
        assert!(matches!(verify(Some(&key), UUID, &ticket, NOW + TTL_SECS + 1), Check::Expired(_)));
    }

    #[test]
    fn missing_and_malformed() {
        let key = key();
        assert_eq!(verify(Some(&key), UUID, "", NOW), Check::Missing);
        assert_eq!(verify(None, UUID, "", NOW), Check::Missing);
        for junk in ["x", "rt1", "rt1.c.1.a.b", "rt1.c.1.a.b.c.d", "rt1.x.1...", "rt1.c.nan...", "rt1.c.1.!!..", "rt1.c.1...short"] {
            assert!(matches!(verify(Some(&key), UUID, junk, NOW), Check::Bad(_)), "{junk}");
        }
        let long = "a".repeat(MAX_TICKET + 1);
        assert_eq!(verify(Some(&key), UUID, &long, NOW), Check::Bad("too long"));
        let ticket = mint(&key, Role::Controller, UUID, "1", "2", NOW);
        assert_eq!(verify(Some(&key), "", &ticket, NOW), Check::Bad("no uuid"));
    }

    #[test]
    fn key_file_made_then_read_back() {
        let dir = std::env::temp_dir().join(format!("relay_ticket_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("relay_ticket.key");
        let path = path.to_str().unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(read_key(path), Ok(None));
        let made = create_key(path, false).unwrap();
        let read = read_key(path).unwrap().unwrap();
        assert!(made == read);
        // A second create keeps the file that is there.
        let again = create_key(path, false).unwrap();
        assert!(again == made);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let ticket = mint(&made, Role::Controller, UUID, "1", "2", NOW);
        assert!(matches!(verify(Some(&read), UUID, &ticket, NOW), Check::Valid(_)));
        // The raw 32 bytes are accepted too; anything else is refused.
        std::fs::write(path, [9u8; 32]).unwrap();
        assert!(read_key(path).unwrap().unwrap() == Key::from_slice(&[9u8; 32]).unwrap());
        std::fs::write(path, b"too short").unwrap();
        assert!(read_key(path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The key file in a fresh directory of its own for the test `name`.
    fn key_path(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("relay_ticket_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("relay_ticket.key").to_str().unwrap().to_owned()
    }

    fn remove_key_dir(path: &str) {
        let _ = std::fs::remove_dir_all(std::path::Path::new(path).parent().unwrap());
    }

    /// Writes `contents` with its modification time `at` seconds past a fixed start, so a rewrite
    /// shows as a change however coarse the filesystem's clock.
    fn write_at(path: &str, contents: &[u8], at: u64) {
        std::fs::write(path, contents).unwrap();
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + at))
            .unwrap();
    }

    fn key_of(byte: u8) -> (Key, String) {
        (Key::from_slice(&[byte; 32]).unwrap(), format!("{}\n", base64::encode([byte; 32])))
    }

    #[test]
    fn a_changed_key_file_is_read_again_and_the_key_before_kept_for_a_while() {
        let path = key_path("changed");
        let (old, old_text) = key_of(1);
        let (new, new_text) = key_of(2);
        write_at(&path, old_text.as_bytes(), 0);
        let mut file = KeyFile::new(path.clone(), false);
        let t0 = Instant::now();
        file.refresh(t0);
        assert!(file.keys(t0) == vec![old.clone()]);
        let ticket = mint(&old, Role::Controller, UUID, "1", "2", NOW);
        write_at(&path, new_text.as_bytes(), 60);
        // Not looked at again before RELOAD_EVERY.
        file.refresh(t0 + RELOAD_EVERY / 2);
        assert!(file.keys(t0 + RELOAD_EVERY / 2) == vec![old.clone()]);
        let t1 = t0 + RELOAD_EVERY;
        file.refresh(t1);
        assert!(file.keys(t1) == vec![new.clone(), old.clone()]);
        // A ticket minted under the key before still verifies, until GRACE is over.
        assert!(matches!(verify_any(&file.keys(t1), UUID, &ticket, NOW), Check::Valid(_)));
        let fresh = mint(&new, Role::Controlled, UUID, "1", "2", NOW);
        assert!(matches!(verify_any(&file.keys(t1), UUID, &fresh, NOW), Check::Valid(_)));
        let t2 = t1 + GRACE;
        assert!(file.keys(t2) == vec![new.clone()]);
        assert!(matches!(verify_any(&file.keys(t2), UUID, &ticket, NOW), Check::Bad(_)));
        // The same key written again isn't a change.
        write_at(&path, new_text.as_bytes(), 120);
        file.refresh(t2);
        assert!(file.keys(t2) == vec![new.clone()]);
        remove_key_dir(&path);
    }

    #[test]
    fn a_key_file_gone_or_broken_keeps_the_key() {
        let path = key_path("broken");
        let (key, text) = key_of(3);
        write_at(&path, text.as_bytes(), 0);
        let mut file = KeyFile::new(path.clone(), true);
        let t0 = Instant::now();
        file.refresh(t0);
        assert!(file.key == Some(key.clone()));
        // A replacement cut short, then none at all: the key read before stays, and hbbs makes no
        // new one while it has a key (hbbr still has that one).
        write_at(&path, b"", 60);
        file.refresh(t0 + RELOAD_EVERY);
        assert!(file.key == Some(key.clone()));
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        std::fs::remove_file(&path).unwrap();
        file.refresh(t0 + RELOAD_EVERY * 2);
        assert!(file.key == Some(key.clone()));
        assert!(file.previous.is_none());
        assert!(!std::path::Path::new(&path).exists());
        remove_key_dir(&path);
    }

    #[test]
    fn hbbs_replaces_an_empty_or_cut_short_key_file_and_hbbr_leaves_it() {
        let cut_short: [&[u8]; 4] = [b"", b"\n", b"c2hvcnQ=", &[0u8; 31]];
        for contents in cut_short {
            let path = key_path("short");
            write_at(&path, contents, 0);
            let t0 = Instant::now();
            let mut hbbr = KeyFile::new(path.clone(), false);
            hbbr.refresh(t0);
            assert!(hbbr.key.is_none());
            assert_eq!(std::fs::read(&path).unwrap(), contents);
            let mut hbbs = KeyFile::new(path.clone(), true);
            hbbs.refresh(t0);
            let made = hbbs.key.clone().unwrap();
            assert!(read_key(&path) == Ok(Some(made.clone())));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
            // hbbr picks the new key up on its next look.
            hbbr.refresh(t0 + RELOAD_EVERY);
            assert!(hbbr.key == Some(made));
            remove_key_dir(&path);
        }
        // A file as long as a key but not one is someone's mistake, not a cut-short write: hbbs
        // leaves it alone and mints nothing.
        let path = key_path("short");
        let junk = "#".repeat(KEY_TEXT_LEN);
        write_at(&path, junk.as_bytes(), 0);
        let mut hbbs = KeyFile::new(path.clone(), true);
        hbbs.refresh(Instant::now());
        assert!(hbbs.key.is_none());
        assert_eq!(std::fs::read(&path).unwrap(), junk.as_bytes());
        remove_key_dir(&path);
    }
}
