//! WebRTC signaling through hbbs (the controller's offer to the target, the target's
//! answer back, and both sides' ICE candidates), only inside a connection request hbbs let through.
//!
//! - Off unless rendezvous_settings says `webrtc=on`, or `webrtc=test` for the target ids listed in
//!   `webrtc-test-ids` (or the WEBRTC env var): otherwise hbbs drops offers, so
//!   clients fall back to their usual route. The switch lives here because ALWAYS_USE_RELAY doesn't
//!   stop WebRTC on the client.
//! - A session opens when a PunchHoleRequest carrying an offer passes the gate, keyed by the
//!   controller's address, and lasts SESSION_TTL. While it is open hbbs keeps the controller's
//!   connection for the answer and the candidates instead of dropping it after the answer.
//! - Candidates: the controller sends {id: target, session_key} on its own connection; the target
//!   sends {socket_addr: the controller's address, session_key} on a connection of its own. The
//!   first session key seen is pinned; MAX_CANDIDATES per direction. Anything else is dropped.
use hbb_common::{log, rendezvous_proto::IceCandidate, try_into_v4, AddrMangle};
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

const SESSION_TTL: Duration = Duration::from_secs(60);
const MAX_CANDIDATES: u32 = 64;
const MAX_SESSIONS: usize = 4096;

/// Whether hbbs forwards a WebRTC offer to `target_id` (see rendezvous_settings): `webrtc=on`, or
/// `webrtc=test` and the id is listed in `webrtc-test-ids` (comma-separated). A controlled device
/// answers any offer with its own STUN servers, so `test` keeps devices without our STUN list out
/// until every client is pinned to it. Changes are logged.
pub(crate) fn enabled_for(target_id: &str) -> bool {
    static LAST: Lazy<Mutex<Option<(String, String)>>> = Lazy::new(|| Mutex::new(None));
    let (value, source) = crate::rendezvous_settings::get("webrtc");
    let mode = match value.as_deref() {
        Some("on" | "y" | "yes" | "true" | "1") => "on",
        Some("test") => "test",
        _ => "off",
    };
    let ids = if mode == "test" {
        crate::rendezvous_settings::get("webrtc-test-ids").0.unwrap_or_default()
    } else {
        String::new()
    };
    {
        let mut last = LAST.lock().unwrap();
        if last.as_ref() != Some(&(mode.to_owned(), ids.clone())) {
            log::info!("webrtc signaling: {} (from {}){}", mode, source,
                if mode == "test" { format!(", test ids: {}", ids) } else { String::new() });
            *last = Some((mode.to_owned(), ids.clone()));
        }
    }
    match mode {
        "on" => true,
        "test" => ids.split(',').any(|id| !id.trim().is_empty() && id.trim() == target_id.to_lowercase()),
        _ => false,
    }
}

struct Session {
    target_id: String,
    target_addr: SocketAddr,
    opened: Instant,
    session_key: Option<String>,
    from_controller: u32,
    from_target: u32,
}

static SESSIONS: Lazy<Mutex<HashMap<SocketAddr, Session>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// Drops expired sessions; returns their controllers, whose kept connections the caller releases.
fn prune(sessions: &mut HashMap<SocketAddr, Session>) -> Vec<SocketAddr> {
    let expired: Vec<SocketAddr> = sessions
        .iter()
        .filter(|(_, s)| s.opened.elapsed() >= SESSION_TTL)
        .map(|(addr, _)| *addr)
        .collect();
    for addr in &expired {
        sessions.remove(addr);
    }
    expired
}

/// A gated request carrying an offer. Returns false (forward no offer) when the table is full.
/// Also returns the expired controllers to release.
pub(crate) fn open(controller: SocketAddr, target_id: &str, target_addr: SocketAddr) -> (bool, Vec<SocketAddr>) {
    let mut sessions = SESSIONS.lock().unwrap();
    let expired = prune(&mut sessions);
    let controller = try_into_v4(controller);
    if sessions.len() >= MAX_SESSIONS && !sessions.contains_key(&controller) {
        log::warn!("webrtc signaling: session table full, offer from {} not forwarded", controller);
        return (false, expired);
    }
    // A retry for the same target keeps the pinned key and counts; a new target starts over.
    let keep = sessions
        .get(&controller)
        .map_or(false, |s| s.target_id == target_id && s.opened.elapsed() < SESSION_TTL);
    if !keep {
        sessions.insert(
            controller,
            Session {
                target_id: target_id.to_owned(),
                target_addr,
                opened: Instant::now(),
                session_key: None,
                from_controller: 0,
                from_target: 0,
            },
        );
    }
    (true, expired)
}

/// Whether `controller` has an open session (so its connection must be kept after the answer).
pub(crate) fn is_open(controller: SocketAddr) -> bool {
    SESSIONS
        .lock()
        .unwrap()
        .get(&try_into_v4(controller))
        .map_or(false, |s| s.opened.elapsed() < SESSION_TTL)
}

pub(crate) enum Route {
    /// From the controller: send to the target's registered (UDP) address.
    ToTarget(SocketAddr),
    /// From the target: send on the controller's kept connection.
    ToController(SocketAddr),
    Drop(&'static str),
}

/// Where a candidate received on a connection from `from` goes, if anywhere.
pub(crate) fn route(from: SocketAddr, ice: &IceCandidate) -> Route {
    if ice.session_key.is_empty() || ice.candidate.is_empty() {
        return Route::Drop("missing session key or candidate");
    }
    let mut sessions = SESSIONS.lock().unwrap();
    prune(&mut sessions);
    let from = try_into_v4(from);
    let (controller, from_controller) = match sessions.get(&from) {
        Some(s) if s.target_id == ice.id => (from, true),
        _ if !ice.socket_addr.is_empty() => (try_into_v4(AddrMangle::decode(&ice.socket_addr)), false),
        _ => return Route::Drop("no session for this connection"),
    };
    let Some(s) = sessions.get_mut(&controller) else {
        return Route::Drop("no session for that controller");
    };
    match &s.session_key {
        Some(key) if *key != ice.session_key => return Route::Drop("session key mismatch"),
        Some(_) => {}
        None => s.session_key = Some(ice.session_key.clone()),
    }
    let count = if from_controller { &mut s.from_controller } else { &mut s.from_target };
    if *count >= MAX_CANDIDATES {
        return Route::Drop("too many candidates");
    }
    *count += 1;
    if from_controller {
        Route::ToTarget(s.target_addr)
    } else {
        Route::ToController(controller)
    }
}
