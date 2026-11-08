use crate::relay_ticket::{Check, Ticket};
use async_speed_limit::Limiter;
use async_trait::async_trait;
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    futures_util::{sink::SinkExt, stream::StreamExt},
    log,
    protobuf::Message as _,
    rendezvous_proto::*,
    sleep,
    tcp::FramedStream,
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{Mutex, RwLock},
        time::{interval, Duration},
    },
    ResultType,
};
use sodiumoxide::crypto::sign;
use std::{
    collections::{HashMap, HashSet},
    io::prelude::*,
    io::Error,
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicUsize, Ordering},
    sync::Arc,
};

type Usage = (usize, usize, usize, usize);
type WaitingPeer = (Arc<()>, Box<dyn StreamTrait>);

lazy_static::lazy_static! {
    // Managed hardening: with its valid relay ticket, for the pairing check.
    static ref PEERS: Mutex<HashMap<String, (WaitingPeer, Option<Ticket>)>> = Default::default();
    static ref USAGE: RwLock<HashMap<String, Usage>> = Default::default();
    static ref BLACKLIST: RwLock<HashSet<String>> = Default::default();
    static ref BLOCKLIST: RwLock<HashSet<String>> = Default::default();
}

static DOWNGRADE_THRESHOLD_100: AtomicUsize = AtomicUsize::new(66); // 0.66
static DOWNGRADE_START_CHECK: AtomicUsize = AtomicUsize::new(1_800_000); // in ms
static LIMIT_SPEED: AtomicUsize = AtomicUsize::new(32 * 1024 * 1024); // in bit/s
static TOTAL_BANDWIDTH: AtomicUsize = AtomicUsize::new(1024 * 1024 * 1024); // in bit/s
static SINGLE_BANDWIDTH: AtomicUsize = AtomicUsize::new(128 * 1024 * 1024); // in bit/s
// Fixed at the handshake, so it is sized for the session a websocket leg carries once paired.
const WS_BUFFER_SIZE: usize = 64 << 10;
const BLACKLIST_FILE: &str = "blacklist.txt";
const BLOCKLIST_FILE: &str = "blocklist.txt";

#[tokio::main(flavor = "multi_thread")]
pub async fn start_with_bind(
    bind_addr: Option<IpAddr>,
    port: &str,
    key: &str,
) -> ResultType<()> {
    let key = get_server_sk(key)?;
    if let Ok(mut file) = std::fs::File::open(BLACKLIST_FILE) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for x in contents.split('\n') {
                if let Some(ip) = x.trim().split(' ').next() {
                    BLACKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
    }
    log::info!(
        "#blacklist({}): {}",
        BLACKLIST_FILE,
        BLACKLIST.read().await.len()
    );
    if let Ok(mut file) = std::fs::File::open(BLOCKLIST_FILE) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for x in contents.split('\n') {
                if let Some(ip) = x.trim().split(' ').next() {
                    BLOCKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
    }
    log::info!(
        "#blocklist({}): {}",
        BLOCKLIST_FILE,
        BLOCKLIST.read().await.len()
    );
    if ticket_mode() != TicketMode::Off {
        let _ = crate::relay_ticket::verifying_keys();
    }
    let port: u16 = port.parse()?;
    log::info!("Listening on tcp :{}", port);
    let port2 = port + 2;
    let ws_bind_addr = crate::common::ws_bind_address(bind_addr)?;
    log::info!("Listening on websocket :{}", port2);
    let main_task = async move {
        loop {
            log::info!("Start");
            io_loop(
                crate::common::listen_tcp(bind_addr, port).await?,
                crate::common::listen_tcp(ws_bind_addr, port2).await?,
                crate::common::listen_console(bind_addr, port).await?,
                &key,
            )
            .await;
        }
    };
    let listen_signal = crate::common::listen_signal();
    tokio::select!(
        res = main_task => res,
        res = listen_signal => res,
    )
}

fn check_params() {
    let tmp = crate::common::get_arg("DOWNGRADE_THRESHOLD")
        .parse::<f64>()
        .unwrap_or(0.);
    if tmp > 0. {
        DOWNGRADE_THRESHOLD_100.store((tmp * 100.) as _, Ordering::SeqCst);
    }
    log::info!(
        "DOWNGRADE_THRESHOLD: {}",
        DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64 / 100.
    );
    let tmp = crate::common::get_arg("DOWNGRADE_START_CHECK")
        .parse::<usize>()
        .unwrap_or(0);
    if tmp > 0 {
        DOWNGRADE_START_CHECK.store(tmp * 1000, Ordering::SeqCst);
    }
    log::info!(
        "DOWNGRADE_START_CHECK: {}s",
        DOWNGRADE_START_CHECK.load(Ordering::SeqCst) / 1000
    );
    let tmp = crate::common::get_arg("LIMIT_SPEED")
        .parse::<f64>()
        .unwrap_or(0.);
    if tmp > 0. {
        LIMIT_SPEED.store((tmp * 1024. * 1024.) as usize, Ordering::SeqCst);
    }
    log::info!(
        "LIMIT_SPEED: {}Mb/s",
        LIMIT_SPEED.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    );
    let tmp = crate::common::get_arg("TOTAL_BANDWIDTH")
        .parse::<f64>()
        .unwrap_or(0.);
    if tmp > 0. {
        TOTAL_BANDWIDTH.store((tmp * 1024. * 1024.) as usize, Ordering::SeqCst);
    }

    log::info!(
        "TOTAL_BANDWIDTH: {}Mb/s",
        TOTAL_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    );
    let tmp = crate::common::get_arg("SINGLE_BANDWIDTH")
        .parse::<f64>()
        .unwrap_or(0.);
    if tmp > 0. {
        SINGLE_BANDWIDTH.store((tmp * 1024. * 1024.) as usize, Ordering::SeqCst);
    }
    log::info!(
        "SINGLE_BANDWIDTH: {}Mb/s",
        SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    )
}

async fn check_cmd(cmd: &str, limiter: Limiter) -> String {
    use std::fmt::Write;

    let mut res = "".to_owned();
    let mut fds = cmd.trim().split(' ');
    match fds.next() {
        Some("h") => {
            res = format!(
                "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                "blacklist-add(ba) <ip>",
                "blacklist-remove(br) <ip>",
                "blacklist(b) <ip>",
                "blocklist-add(Ba) <ip>",
                "blocklist-remove(Br) <ip>",
                "blocklist(B) <ip>",
                "downgrade-threshold(dt) [value]",
                "downgrade-start-check(t) [value(second)]",
                "limit-speed(ls) [value(Mb/s)]",
                "total-bandwidth(tb) [value(Mb/s)]",
                "single-bandwidth(sb) [value(Mb/s)]",
                "usage(u)"
            )
        }
        Some("blacklist-add" | "ba") => {
            if let Some(ip) = fds.next() {
                for ip in ip.split('|') {
                    BLACKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
        Some("blacklist-remove" | "br") => {
            if let Some(ip) = fds.next() {
                if ip == "all" {
                    BLACKLIST.write().await.clear();
                } else {
                    for ip in ip.split('|') {
                        BLACKLIST.write().await.remove(ip);
                    }
                }
            }
        }
        Some("blacklist" | "b") => {
            if let Some(ip) = fds.next() {
                res = format!("{}\n", BLACKLIST.read().await.get(ip).is_some());
            } else {
                for ip in BLACKLIST.read().await.clone().into_iter() {
                    let _ = writeln!(res, "{ip}");
                }
            }
        }
        Some("blocklist-add" | "Ba") => {
            if let Some(ip) = fds.next() {
                for ip in ip.split('|') {
                    BLOCKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
        Some("blocklist-remove" | "Br") => {
            if let Some(ip) = fds.next() {
                if ip == "all" {
                    BLOCKLIST.write().await.clear();
                } else {
                    for ip in ip.split('|') {
                        BLOCKLIST.write().await.remove(ip);
                    }
                }
            }
        }
        Some("blocklist" | "B") => {
            if let Some(ip) = fds.next() {
                res = format!("{}\n", BLOCKLIST.read().await.get(ip).is_some());
            } else {
                for ip in BLOCKLIST.read().await.clone().into_iter() {
                    let _ = writeln!(res, "{ip}");
                }
            }
        }
        Some("downgrade-threshold" | "dt") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        DOWNGRADE_THRESHOLD_100.store((v * 100.) as _, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!(
                    "{}\n",
                    DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64 / 100.
                );
            }
        }
        Some("downgrade-start-check" | "t") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<usize>() {
                    if v > 0 {
                        DOWNGRADE_START_CHECK.store(v * 1000, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!("{}s\n", DOWNGRADE_START_CHECK.load(Ordering::SeqCst) / 1000);
            }
        }
        Some("limit-speed" | "ls") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        LIMIT_SPEED.store((v * 1024. * 1024.) as _, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    LIMIT_SPEED.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("total-bandwidth" | "tb") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        TOTAL_BANDWIDTH.store((v * 1024. * 1024.) as _, Ordering::SeqCst);
                        limiter.set_speed_limit(TOTAL_BANDWIDTH.load(Ordering::SeqCst) as _);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    TOTAL_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("single-bandwidth" | "sb") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        SINGLE_BANDWIDTH.store((v * 1024. * 1024.) as _, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("usage" | "u") => {
            let mut tmp: Vec<(String, Usage)> = USAGE
                .read()
                .await
                .iter()
                .map(|x| (x.0.clone(), *x.1))
                .collect();
            tmp.sort_by(|a, b| ((b.1).1).partial_cmp(&(a.1).1).unwrap());
            for (ip, (elapsed, total, highest, speed)) in tmp {
                if elapsed == 0 {
                    continue;
                }
                let _ = writeln!(
                    res,
                    "{}: {}s {:.2}MB {}kb/s {}kb/s {}kb/s",
                    ip,
                    elapsed / 1000,
                    total as f64 / 1024. / 1024. / 8.,
                    highest,
                    total / elapsed,
                    speed
                );
            }
        }
        _ => {}
    }
    res
}

async fn io_loop(
    listener: TcpListener,
    listener2: TcpListener,
    listener_console: Option<TcpListener>,
    key: &str,
) {
    check_params();
    let limiter = <Limiter>::new(TOTAL_BANDWIDTH.load(Ordering::SeqCst) as _);
    loop {
        tokio::select! {
            res = listener.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &limiter, key, false).await;
                    }
                    Err(err) => {
                       log::error!("listener.accept failed: {}", err);
                       break;
                    }
                }
            }
            res = listener2.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &limiter, key, true).await;
                    }
                    Err(err) => {
                       log::error!("listener2.accept failed: {}", err);
                       break;
                    }
                }
            }
            res = crate::common::accept_or_pending(listener_console.as_ref()) => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &limiter, key, false).await;
                    }
                    Err(err) => {
                       log::error!("console listener.accept failed: {}", err);
                       break;
                    }
                }
            }
        }
    }
}

/// Accepts a relay connection and routes loopback console requests separately.
async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    limiter: &Limiter,
    key: &str,
    ws: bool,
) {
    let ip = hbb_common::try_into_v4(addr).ip();
    if !ws && ip.is_loopback() {
        let limiter = limiter.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let mut buffer = [0; 1024];
            if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                    let res = check_cmd(data, limiter).await;
                    if let Err(err) = timeout(1000, stream.write_all(res.as_bytes()))
                        .await
                        .unwrap_or_else(|elapsed| Err(elapsed.into()))
                    {
                        log::warn!("Failed to send the console reply: {err}");
                    }
                }
            }
        });
        return;
    }
    let ip = ip.to_string();
    if BLOCKLIST.read().await.get(&ip).is_some() {
        log::info!("{} blocked", ip);
        return;
    }
    let key = key.to_owned();
    let limiter = limiter.clone();
    tokio::spawn(async move {
        allow_err!(make_pair(stream, addr, &key, limiter, ws).await);
    });
}

/// Prepares a TCP or WebSocket relay stream and begins pairing.
async fn make_pair(
    stream: TcpStream,
    mut addr: SocketAddr,
    key: &str,
    limiter: Limiter,
    ws: bool,
) -> ResultType<()> {
    if ws {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
        let callback = |req: &Request, response: Response| {
            let headers = req.headers();
            // X-Real-IP / X-Forwarded-For are trusted as-is so that the real
            // client IP is preserved when the WebSocket port runs behind a
            // reverse proxy (WSS). They are NOT validated: anyone who can reach
            // this port directly can spoof an arbitrary IP, bypassing IP-based
            // rate limiting / blocking and corrupting logged IPs. Do not expose
            // the WebSocket port directly to untrusted networks; only the
            // reverse proxy, which overwrites these headers, should be able to
            // connect to it.
            // https://github.com/rustdesk/rustdesk-server/issues/634
            let real_ip = headers
                .get("X-Real-IP")
                .or_else(|| headers.get("X-Forwarded-For"))
                .and_then(|header_value| header_value.to_str().ok());
            if let Some(ip) = real_ip {
                if let Ok(ip) = ip.parse() {
                    addr = SocketAddr::new(ip, addr.port());
                }
            }
            Ok(response)
        };
        // The message bound is set in make_pair_, once the handshake is done.
        let ws_config = tungstenite::protocol::WebSocketConfig::default()
            .read_buffer_size(WS_BUFFER_SIZE)
            .write_buffer_size(WS_BUFFER_SIZE);
        let ws_stream = timeout(
            30_000,
            tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(ws_config)),
        )
        .await??;
        make_pair_(ws_stream, addr, key, limiter).await;
    } else {
        make_pair_(FramedStream::from(stream, addr), addr, key, limiter).await;
    }
    Ok(())
}

// Hardening: an unpaired connection has sent nothing but its RequestRelay, which is
// tiny, so this bounds what it can make hbbr buffer; the bound is lifted on both
// ends once the pair is made, for the session's own traffic.
const UNPAIRED_MAX_MESSAGE: usize = 64 * 1024;
// What a paired WebSocket leg is lifted to (the sec3 values, below tungstenite's 64 MiB message /
// 16 MiB frame defaults); before pairing it is held to UNPAIRED_MAX_MESSAGE like a framed leg.
const WS_MAX_FRAME: usize = 4 << 20;
const WS_MAX_MESSAGE: usize = 16 << 20;

/// Checks a configured relay key and pairs a request with a waiting connection.
async fn make_pair_(stream: impl StreamTrait, addr: SocketAddr, key: &str, limiter: Limiter) {
    let mut stream = stream;
    stream.set_max_packet_length(UNPAIRED_MAX_MESSAGE);
    if let Ok(Some(Ok(bytes))) = timeout(30_000, stream.recv()).await {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
            if let Some(rendezvous_message::Union::RequestRelay(rf)) = msg_in.union {
                if !key.is_empty() && rf.licence_key != key {
                    log::warn!("Relay authentication failed from {} - invalid key", addr);
                    return;
                }
                if !rf.uuid.is_empty() {
                    // Managed hardening: hbbs's relay ticket, each side's checked on its own, then the two
                    // against each other.
                    let mode = ticket_mode();
                    let Ok(ticket) = check_ticket(mode, &rf.uuid, &rf.relay_ticket, addr) else {
                        return;
                    };
                    let mut peers = PEERS.lock().await;
                    let Ok(waiting) = take_waiting(&mut *peers, mode, &rf.uuid, ticket.as_ref(), addr)
                    else {
                        return;
                    };
                    if let Some((_, mut peer)) = waiting {
                        drop(peers);
                        log::info!("Relayrequest {} from {} got paired", rf.uuid, addr);
                        stream.set_max_packet_length(usize::MAX);
                        peer.set_max_packet_length(usize::MAX);
                        let id = format!("{}:{}", addr.ip(), addr.port());
                        USAGE.write().await.insert(id.clone(), Default::default());
                        if !stream.is_ws() && !peer.is_ws() {
                            peer.set_raw();
                            stream.set_raw();
                            log::info!("Both are raw");
                        }
                        if let Err(err) = relay(addr, &mut stream, &mut peer, limiter, id.clone()).await
                        {
                            log::info!("Relay of {} closed: {}", addr, err);
                        } else {
                            log::info!("Relay of {} closed", addr);
                        }
                        USAGE.write().await.remove(&id);
                    } else {
                        log::info!("New relay request {} from {}", rf.uuid, addr);
                        let generation = Arc::new(());
                        peers.insert(rf.uuid.clone(), ((generation.clone(), Box::new(stream)), ticket));
                        drop(peers);
                        sleep(30.).await;
                        expire_waiter(&mut *PEERS.lock().await, &rf.uuid, &generation);
                    }
                }
            }
        }
    }
}

/// Managed hardening: what hbbr does with relay tickets: `ticket_mode` in relay_settings (else the
/// TICKET_MODE environment variable). `off` checks nothing; `log`, the default, checks and logs
/// every ticket and refuses nothing; `enforce` refuses a connection whose ticket is missing, bad or
/// expired. Changes are logged; a value that names no mode means log, with a warning.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TicketMode {
    Off,
    Log,
    Enforce,
}

/// The mode a ticket_mode setting names, None for a value that names none. Unset (or empty) is
/// the default, log.
fn parse_ticket_mode(value: Option<&str>) -> Option<TicketMode> {
    match value {
        None | Some("") | Some("log") => Some(TicketMode::Log),
        Some("off") => Some(TicketMode::Off),
        Some("enforce") => Some(TicketMode::Enforce),
        Some(_) => None,
    }
}

/// The ticket_mode setting last seen and the mode it meant, so each change is logged once.
#[derive(Default)]
struct ModeSeen(Option<(Option<String>, TicketMode)>);

/// What a look at the setting found.
#[derive(Debug, PartialEq)]
struct ModeNews {
    mode: TicketMode,
    /// The mode differs from the last look's.
    changed: bool,
    /// The setting changed to a value that names no mode (so it means log).
    unknown: bool,
}

impl ModeSeen {
    fn see(&mut self, value: Option<String>) -> ModeNews {
        if let Some((last, mode)) = &self.0 {
            if *last == value {
                return ModeNews { mode: *mode, changed: false, unknown: false };
            }
        }
        let parsed = parse_ticket_mode(value.as_deref());
        let mode = parsed.unwrap_or(TicketMode::Log);
        let changed = self.0.as_ref().map_or(true, |(_, last)| *last != mode);
        self.0 = Some((value, mode));
        ModeNews { mode, changed, unknown: parsed.is_none() }
    }
}

fn ticket_mode() -> TicketMode {
    static SEEN: once_cell::sync::Lazy<std::sync::Mutex<ModeSeen>> =
        once_cell::sync::Lazy::new(Default::default);
    let (value, source) = crate::relay_settings::get("ticket_mode");
    let news = SEEN.lock().unwrap().see(value.clone());
    if news.unknown {
        log::warn!(
            "relay ticket mode: {:?} (from {}) is not off, log or enforce; using {:?}",
            value.unwrap_or_default(),
            source,
            news.mode
        );
    } else if news.changed {
        log::info!("relay ticket mode: {:?} (from {})", news.mode, source);
    }
    news.mode
}

/// Whether `mode` lets a connection with this ticket wait or pair.
fn ticket_allows(mode: TicketMode, check: &Check) -> bool {
    mode != TicketMode::Enforce || matches!(check, Check::Valid(_))
}

/// Why two valid tickets on one uuid can't be its two ends, if they can't: they must be for
/// opposite sides of the same relay between the same two devices, so one side's ticket can't open
/// both ends, nor tickets hbbs minted for one pair of devices the other end of another's relay.
fn mismatch(a: &Ticket, b: &Ticket) -> Option<&'static str> {
    if a.role == b.role {
        Some("same side")
    } else if a.uuid != b.uuid {
        Some("another relay")
    } else if a.controller_id != b.controller_id || a.controlled_id != b.controlled_id {
        Some("other devices")
    } else {
        None
    }
}

/// Whether `mode` lets two connections whose valid tickets are `a` and `b` pair. A side without
/// one (let through in log mode) isn't compared.
fn pair_allows(mode: TicketMode, a: Option<&Ticket>, b: Option<&Ticket>) -> bool {
    mode != TicketMode::Enforce || a.zip(b).and_then(|(a, b)| mismatch(a, b)).is_none()
}

/// At most 64 characters of what a client sent, for the log.
fn short(s: &str) -> &str {
    match s.char_indices().nth(64) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// Checks the relay ticket of a RequestRelay for `uuid` from `addr` and logs the outcome. Err: the
/// connection is refused. Ok: the ticket, when valid (None for any other outcome let through).
fn check_ticket(
    mode: TicketMode,
    uuid: &str,
    ticket: &str,
    addr: SocketAddr,
) -> Result<Option<Ticket>, ()> {
    if mode == TicketMode::Off {
        return Ok(None);
    }
    let now = crate::relay_ticket::now_secs();
    let check = crate::relay_ticket::verify_any(
        &crate::relay_ticket::verifying_keys(),
        uuid,
        ticket,
        now,
    );
    let allowed = ticket_allows(mode, &check);
    let detail = match &check {
        Check::Valid(t) | Check::Expired(t) => format!(
            " ({} side, {:?} -> {:?}, expiry {}s {})",
            t.role.as_str(),
            short(&t.controller_id),
            short(&t.controlled_id),
            t.expiry.abs_diff(now),
            if t.expiry >= now { "ahead" } else { "ago" }
        ),
        Check::Bad(why) => format!(" ({})", why),
        Check::Missing => String::new(),
    };
    let verdict = match (allowed, &check) {
        (_, Check::Valid(_)) => "",
        (true, _) => ", allowed (log mode)",
        (false, _) => ", refused",
    };
    log::info!(
        "relay ticket {}: uuid {} from {}{}{}",
        check.outcome(),
        short(uuid),
        addr,
        detail,
        verdict
    );
    match check {
        Check::Valid(t) => Ok(Some(t)),
        _ if allowed => Ok(None),
        _ => Err(()),
    }
}

/// What the connection from `addr` to `uuid`, whose valid ticket is `ticket` (if any), pairs with:
/// the side waiting there, taken out of `peers`, or None, to wait itself. Err: `mode` refuses the
/// pair, and only this connection: the side waiting stays for its own partner. Tickets that don't
/// match are logged.
fn take_waiting<S>(
    peers: &mut HashMap<String, (S, Option<Ticket>)>,
    mode: TicketMode,
    uuid: &str,
    ticket: Option<&Ticket>,
    addr: SocketAddr,
) -> Result<Option<S>, ()> {
    let Some((_, waiting)) = peers.get(uuid) else {
        return Ok(None);
    };
    let waiting = waiting.as_ref();
    if let Some((ours, why)) = ticket.zip(waiting).and_then(|(a, b)| Some((a, mismatch(a, b)?))) {
        let allowed = pair_allows(mode, ticket, waiting);
        log::warn!(
            "relay ticket: uuid {} from {} has a {} ticket that doesn't match the side waiting ({}){}",
            short(uuid),
            addr,
            ours.role.as_str(),
            why,
            if allowed { ", allowed (log mode)" } else { ", refused" }
        );
        if !allowed {
            return Err(());
        }
    }
    Ok(peers.remove(uuid).map(|(peer, _)| peer))
}

/// Removes a waiting connection only if it still owns the requested pair ID.
fn expire_waiter(
    peers: &mut HashMap<String, (WaitingPeer, Option<Ticket>)>,
    id: &str,
    generation: &Arc<()>,
) {
    if peers.get(id).map(|((current, _), _)| Arc::ptr_eq(current, generation)).unwrap_or(false) {
        peers.remove(id);
    }
}

/// Forwards traffic in both directions while enforcing relay limits and timeouts.
async fn relay(
    addr: SocketAddr,
    stream: &mut impl StreamTrait,
    peer: &mut Box<dyn StreamTrait>,
    total_limiter: Limiter,
    id: String,
) -> ResultType<()> {
    let ip = addr.ip().to_string();
    let mut tm = std::time::Instant::now();
    let mut elapsed = 0;
    let mut total = 0;
    let mut total_s = 0;
    let mut highest_s = 0;
    let mut downgrade: bool = false;
    let mut blacked: bool = false;
    let sb = SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64;
    let limiter = <Limiter>::new(sb);
    let blacklist_limiter = <Limiter>::new(LIMIT_SPEED.load(Ordering::SeqCst) as _);
    let downgrade_threshold =
        (sb * DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64 / 100. / 1000.) as usize; // in bit/ms
    let mut timer = interval(Duration::from_secs(3));
    let mut last_recv_time = std::time::Instant::now();
    loop {
        tokio::select! {
            res = peer.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    } else {
                        limiter.consume(nb).await;
                    }
                    total_limiter.consume(nb).await;
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        timeout(30_000, stream.send_raw(bytes.into())).await??;
                    }
                } else {
                    break;
                }
            },
            res = stream.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    } else {
                        limiter.consume(nb).await;
                    }
                    total_limiter.consume(nb).await;
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        timeout(30_000, peer.send_raw(bytes.into())).await??;
                    }
                } else {
                    break;
                }
            },
            _ = timer.tick() => {
                if last_recv_time.elapsed().as_secs() > 30 {
                    bail!("Timeout");
                }
            }
        }

        let n = tm.elapsed().as_millis() as usize;
        if n >= 1_000 {
            if BLOCKLIST.read().await.get(&ip).is_some() {
                log::info!("{} blocked", ip);
                break;
            }
            blacked = BLACKLIST.read().await.get(&ip).is_some();
            tm = std::time::Instant::now();
            let speed = total_s / n;
            if speed > highest_s {
                highest_s = speed;
            }
            elapsed += n;
            USAGE.write().await.insert(
                id.clone(),
                (elapsed as _, total as _, highest_s as _, speed as _),
            );
            total_s = 0;
            if elapsed > DOWNGRADE_START_CHECK.load(Ordering::SeqCst)
                && !downgrade
                && total > elapsed * downgrade_threshold
            {
                downgrade = true;
                log::info!(
                    "Downgrade {}, exceed downgrade threshold {}bit/ms in {}ms",
                    id,
                    downgrade_threshold,
                    elapsed
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestStream {
        data: Option<BytesMut>,
        blocked: bool,
    }

    #[async_trait]
    impl StreamTrait for TestStream {
        /// Provides the test stream receive behavior.
        async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
            match self.data.take() {
                Some(data) => Some(Ok(data)),
                None => std::future::pending().await,
            }
        }
        /// Simulates a relay write for the test stream.
        async fn send_raw(&mut self, _: Bytes) -> ResultType<()> {
            if self.blocked { std::future::pending().await } else { Ok(()) }
        }
        /// Uses non-WebSocket framing for the test stream.
        fn is_ws(&self) -> bool { false }
        /// Leaves the test stream unchanged when raw mode is requested.
        fn set_raw(&mut self) {}
        fn set_max_packet_length(&mut self, _: usize) {}
    }

    /// Checks that a blocked relay write ends with a timeout in the selected direction.
    async fn check_blocked_send(from_peer: bool) {
        let mut stream = TestStream {
            data: if from_peer { None } else { Some(BytesMut::from(&b"x"[..])) },
            blocked: from_peer,
        };
        let mut peer: Box<dyn StreamTrait> = Box::new(TestStream {
            data: if from_peer { Some(BytesMut::from(&b"x"[..])) } else { None },
            blocked: !from_peer,
        });
        let result = timeout(35_000, relay(
            "127.0.0.1:1".parse().unwrap(), &mut stream, &mut peer,
            Limiter::new(1_000_000.), "blocked-send-test".to_owned(),
        )).await.expect("a blocked relay write must finish within its deadline");
        let error = result.expect_err("the blocked write must fail");
        assert!(error.downcast_ref::<tokio::time::error::Elapsed>().is_some());
    }

    /// Checks that stalled writes time out in either relay direction.
    #[tokio::test]
    async fn blocked_writes_in_both_directions_time_out() {
        tokio::join!(check_blocked_send(false), check_blocked_send(true));
    }
}

/// Returns the configured relay key or resolves a signing key to its public value.
fn get_server_sk(key: &str) -> ResultType<String> {
    let mut key = key.to_owned();
    if let Ok(sk) = base64::decode(&key) {
        if sk.len() == sign::SECRETKEYBYTES {
            log::info!("The key is a crypto private key");
            key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
        }
    }

    if key == "-" || key == "_" {
        let (pk, _) = crate::common::gen_sk(300)?;
        key = pk;
    }

    if !key.is_empty() {
        log::info!("Key: {}", key);
    }

    Ok(key)
}

#[async_trait]
trait StreamTrait: Send + Sync + 'static {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>>;
    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()>;
    fn is_ws(&self) -> bool;
    fn set_raw(&mut self);
    fn set_max_packet_length(&mut self, n: usize);
}

#[async_trait]
impl StreamTrait for FramedStream {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
        self.next().await
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        self.send_bytes(bytes).await
    }

    fn is_ws(&self) -> bool {
        false
    }

    fn set_raw(&mut self) {
        self.set_raw();
    }

    fn set_max_packet_length(&mut self, n: usize) {
        self.codec_mut().set_max_packet_length(n);
    }
}

#[async_trait]
impl StreamTrait for tokio_tungstenite::WebSocketStream<TcpStream> {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
        if let Some(msg) = self.next().await {
            match msg {
                Ok(msg) => {
                    match msg {
                        tungstenite::Message::Binary(bytes) => {
                            Some(Ok(bytes[..].into())) // to-do: poor performance
                        }
                        _ => Some(Ok(BytesMut::new())),
                    }
                }
                Err(err) => Some(Err(Error::new(std::io::ErrorKind::Other, err.to_string()))),
            }
        } else {
            None
        }
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        Ok(self.send(tungstenite::Message::Binary(bytes)).await?)
    }

    fn is_ws(&self) -> bool {
        true
    }

    fn set_raw(&mut self) {}

    fn set_max_packet_length(&mut self, n: usize) {
        self.set_config(|c| {
            c.max_message_size = Some(n.min(WS_MAX_MESSAGE));
            c.max_frame_size = Some(n.min(WS_MAX_FRAME));
        });
    }
}

#[cfg(test)]
mod ticket_tests {
    use super::*;
    use crate::relay_ticket::{mint, Role};

    fn ticket(role: Role, uuid: &str, controller_id: &str, controlled_id: &str) -> Ticket {
        Ticket {
            role,
            expiry: 0,
            uuid: uuid.into(),
            controller_id: controller_id.into(),
            controlled_id: controlled_id.into(),
        }
    }

    fn valid(role: Role) -> Check {
        Check::Valid(ticket(role, "u", "", ""))
    }

    fn addr() -> SocketAddr {
        "192.0.2.1:40000".parse().unwrap()
    }

    #[test]
    fn log_mode_lets_everything_through_and_enforce_only_valid_tickets() {
        let expired = Check::Expired(ticket(Role::Controller, "u", "", ""));
        for check in [Check::Missing, Check::Bad("x"), expired] {
            assert!(ticket_allows(TicketMode::Off, &check));
            assert!(ticket_allows(TicketMode::Log, &check));
            assert!(!ticket_allows(TicketMode::Enforce, &check));
        }
        for mode in [TicketMode::Off, TicketMode::Log, TicketMode::Enforce] {
            assert!(ticket_allows(mode, &valid(Role::Controlled)));
        }
    }

    #[test]
    fn enforce_pairs_only_opposite_sides_of_the_same_relay() {
        let c = ticket(Role::Controller, "u", "a", "b");
        let t = ticket(Role::Controlled, "u", "a", "b");
        assert!(pair_allows(TicketMode::Enforce, Some(&c), Some(&t)));
        assert!(pair_allows(TicketMode::Enforce, Some(&t), Some(&c)));
        assert!(!pair_allows(TicketMode::Enforce, Some(&c), Some(&c)));
        assert!(!pair_allows(TicketMode::Enforce, Some(&t), Some(&t)));
        assert!(pair_allows(TicketMode::Log, Some(&t), Some(&t)));
        assert!(pair_allows(TicketMode::Log, None, Some(&t)));
        assert!(pair_allows(TicketMode::Enforce, None, None));
        // Opposite sides, but of another pair of devices or another relay.
        for other in [
            ticket(Role::Controlled, "u", "x", "b"),
            ticket(Role::Controlled, "u", "a", "x"),
            ticket(Role::Controlled, "v", "a", "b"),
        ] {
            assert!(!pair_allows(TicketMode::Enforce, Some(&c), Some(&other)), "{other:?}");
            assert!(pair_allows(TicketMode::Log, Some(&c), Some(&other)), "{other:?}");
        }
    }

    #[test]
    fn tickets_minted_for_other_devices_cant_open_the_other_end_of_a_relay() {
        // The victim's controller waits on uuid X with its ticket; the attacker got hbbs to mint
        // it the controlled side's ticket for X too, but naming its own two devices.
        let key = sodiumoxide::crypto::auth::hmacsha256::Key::from_slice(&[5u8; 32]).unwrap();
        let now = 1_800_000_000;
        let checked = |role, controller_id, controlled_id| {
            let minted = mint(&key, role, "X", controller_id, controlled_id, now);
            match crate::relay_ticket::verify_any(&[key.clone()], "X", &minted, now) {
                Check::Valid(t) => t,
                other => panic!("{other:?}"),
            }
        };
        let victim = checked(Role::Controller, "victim-c", "victim-t");
        let attacker = checked(Role::Controlled, "attacker-1", "attacker-2");
        let mut peers = HashMap::from([("X".to_owned(), ("victim", Some(victim)))]);
        assert_eq!(
            take_waiting(&mut peers, TicketMode::Enforce, "X", Some(&attacker), addr()),
            Err(())
        );
        let partner = checked(Role::Controlled, "victim-c", "victim-t");
        assert_eq!(
            take_waiting(&mut peers, TicketMode::Enforce, "X", Some(&partner), addr()),
            Ok(Some("victim"))
        );
    }

    #[test]
    fn a_refused_newcomer_leaves_the_side_waiting_in_place() {
        let mut peers = HashMap::new();
        peers.insert("u".to_owned(), ("legit", Some(ticket(Role::Controller, "u", "a", "b"))));
        // A second controller-side ticket in enforce: refused, and the legitimate side waits on.
        let dup = ticket(Role::Controller, "u", "a", "b");
        assert_eq!(take_waiting(&mut peers, TicketMode::Enforce, "u", Some(&dup), addr()), Err(()));
        assert!(peers.contains_key("u"));
        // Its partner then pairs with it.
        let partner = ticket(Role::Controlled, "u", "a", "b");
        assert_eq!(
            take_waiting(&mut peers, TicketMode::Enforce, "u", Some(&partner), addr()),
            Ok(Some("legit"))
        );
        assert!(peers.is_empty());
        // Nothing waiting: the newcomer waits itself.
        assert_eq!(take_waiting(&mut peers, TicketMode::Enforce, "u", Some(&partner), addr()), Ok(None));
        // Log mode pairs the duplicate anyway (and logs it); no ticket isn't compared.
        peers.insert("u".to_owned(), ("legit", Some(ticket(Role::Controller, "u", "a", "b"))));
        assert_eq!(take_waiting(&mut peers, TicketMode::Log, "u", Some(&dup), addr()), Ok(Some("legit")));
        peers.insert("u".to_owned(), ("legit", Some(ticket(Role::Controller, "u", "a", "b"))));
        assert_eq!(take_waiting(&mut peers, TicketMode::Enforce, "u", None, addr()), Ok(Some("legit")));
    }

    #[test]
    fn an_unknown_ticket_mode_means_log_and_is_warned_about_once_per_change() {
        let news = |mode, changed, unknown| ModeNews { mode, changed, unknown };
        let mut seen = ModeSeen::default();
        assert_eq!(seen.see(None), news(TicketMode::Log, true, false));
        assert_eq!(seen.see(Some("enforce".into())), news(TicketMode::Enforce, true, false));
        assert_eq!(seen.see(Some("enforce".into())), news(TicketMode::Enforce, false, false));
        // A typo: log, warned about once while it stays.
        assert_eq!(seen.see(Some("enforced".into())), news(TicketMode::Log, true, true));
        assert_eq!(seen.see(Some("enforced".into())), news(TicketMode::Log, false, false));
        // Another bad value is warned about again, though the mode stays log.
        assert_eq!(seen.see(Some("on".into())), news(TicketMode::Log, false, true));
        assert_eq!(seen.see(Some("log".into())), news(TicketMode::Log, false, false));
        assert_eq!(seen.see(Some("".into())), news(TicketMode::Log, false, false));
        assert_eq!(seen.see(Some("off".into())), news(TicketMode::Off, true, false));
    }

    #[test]
    fn a_settings_file_that_cant_be_read_keeps_the_values_last_read() {
        use std::io::ErrorKind;
        let mut cache = crate::relay_settings::Cache::default();
        cache.take_read(Ok("# no value\nTicket_Mode = Enforce\n".into()));
        assert_eq!(cache.value("ticket_mode"), Some("enforce"));
        cache.take_read(Err(Error::from(ErrorKind::PermissionDenied)));
        assert_eq!(cache.value("ticket_mode"), Some("enforce"));
        cache.take_read(Err(Error::from(ErrorKind::InvalidData)));
        assert_eq!(cache.value("ticket_mode"), Some("enforce"));
        // A file that's gone has no settings: the environment's apply.
        cache.take_read(Err(Error::from(ErrorKind::NotFound)));
        assert_eq!(cache.value("ticket_mode"), None);
    }

    #[test]
    fn short_cuts_at_a_character() {
        assert_eq!(short("abc"), "abc");
        let long = "é".repeat(100);
        assert_eq!(short(&long).chars().count(), 64);
    }
}

#[cfg(test)]
mod message_size_tests {
    use super::*;
    use hbb_common::{bytes_codec::BytesCodec, tokio_util::codec::Encoder};

    async fn serve_one(ws: bool) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, addr) = listener.accept().await.unwrap();
            allow_err!(make_pair(stream, addr, "", <Limiter>::new(f64::INFINITY), ws).await);
        });
        addr
    }

    fn relay_request(uuid: &str) -> Vec<u8> {
        let mut msg = RendezvousMessage::new();
        msg.set_request_relay(RequestRelay {
            uuid: uuid.to_owned(),
            ..Default::default()
        });
        msg.write_to_bytes().unwrap()
    }

    #[hbb_common::tokio::test]
    async fn relay_request_over_the_bound_is_refused_on_its_header() {
        let addr = serve_one(false).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let payload_len = UNPAIRED_MAX_MESSAGE + 1;
        let mut frame = BytesMut::new();
        BytesCodec::new()
            .encode(Bytes::from(vec![0u8; payload_len]), &mut frame)
            .unwrap();
        client.write_all(&frame[..frame.len() - payload_len]).await.unwrap();
        let mut byte = [0u8; 1];
        let read = timeout(5_000, client.read(&mut byte))
            .await
            .expect("hbbr waited for the payload of an oversized relay request");
        assert_eq!(read.unwrap(), 0);
    }

    async fn ws_client(addr: SocketAddr) -> tokio_tungstenite::WebSocketStream<TcpStream> {
        let stream = TcpStream::connect(addr).await.unwrap();
        tokio_tungstenite::client_async(format!("ws://{addr}"), stream)
            .await
            .unwrap()
            .0
    }

    #[hbb_common::tokio::test]
    async fn ws_relay_request_over_the_bound_is_refused_on_its_header() {
        let addr = serve_one(true).await;
        let mut ws = ws_client(addr).await;
        let client = ws.get_mut();
        let mut header = vec![0x82, 0xff];
        header.extend_from_slice(&(UNPAIRED_MAX_MESSAGE as u64 + 1).to_be_bytes());
        header.extend_from_slice(&[1, 2, 3, 4]);
        client.write_all(&header).await.unwrap();
        let mut buf = [0u8; 256];
        let closed = timeout(5_000, async {
            while client.read(&mut buf).await.unwrap_or(0) > 0 {}
        })
        .await;
        assert!(closed.is_ok(), "hbbr waited for the payload of an oversized relay request");
    }

    #[hbb_common::tokio::test]
    async fn paired_legs_carry_frames_past_the_relay_request_bound() {
        let uuid = "paired-legs";
        let ws_addr = serve_one(true).await;
        let tcp_addr = serve_one(false).await;
        let mut ws = ws_client(ws_addr).await;
        ws.send(tungstenite::Message::Binary(relay_request(uuid).into()))
            .await
            .unwrap();
        // Park the websocket leg first, so the tcp leg is the one that pairs.
        timeout(5_000, async {
            while !PEERS.lock().await.contains_key(uuid) {
                sleep(0.01).await;
            }
        })
        .await
        .expect("websocket leg never parked");
        let mut tcp = FramedStream::from(TcpStream::connect(tcp_addr).await.unwrap(), tcp_addr);
        tcp.send_bytes(relay_request(uuid).into()).await.unwrap();
        let big = vec![7u8; UNPAIRED_MAX_MESSAGE * 2];
        tcp.send_bytes(big.clone().into()).await.unwrap();
        let got = timeout(5_000, ws.next())
            .await
            .expect("relay did not forward the tcp frame")
            .expect("relay closed the websocket leg")
            .unwrap();
        assert_eq!(got.into_data(), big);
        ws.send(tungstenite::Message::Binary(big.clone().into()))
            .await
            .unwrap();
        let got = tcp
            .next_timeout(5_000)
            .await
            .expect("relay did not forward the websocket message")
            .unwrap();
        assert_eq!(&got[..], &big[..]);
    }
}

#[cfg(test)]
mod waiter_tests {
    use super::*;

    struct TestStream;

    #[async_trait]
    impl StreamTrait for TestStream {
        /// Provides the test stream receive behavior.
        async fn recv(&mut self) -> Option<Result<BytesMut, Error>> { None }
        /// Simulates a relay write for the test stream.
        async fn send_raw(&mut self, _: Bytes) -> ResultType<()> { Ok(()) }
        /// Uses non-WebSocket framing for the test stream.
        fn is_ws(&self) -> bool { false }
        /// Leaves the test stream unchanged when raw mode is requested.
        fn set_raw(&mut self) {}
        fn set_max_packet_length(&mut self, _: usize) {}
    }

    /// Checks that an old timeout cannot remove a replacement waiter.
    #[test]
    fn old_waiter_cannot_expire_a_reused_pair_id() {
        let old = Arc::new(());
        let current = Arc::new(());
        let mut peers: HashMap<String, (WaitingPeer, Option<Ticket>)> = HashMap::new();
        peers.insert("pair".to_owned(), ((current.clone(), Box::new(TestStream)), None));
        expire_waiter(&mut peers, "pair", &old);
        assert!(peers.contains_key("pair"));
        expire_waiter(&mut peers, "pair", &current);
        assert!(!peers.contains_key("pair"));
    }
}
