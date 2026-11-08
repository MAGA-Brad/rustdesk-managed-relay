use crate::common::*;
use crate::peer::*;
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config,
    futures::future::join_all,
    futures_util::{
        sink::SinkExt,
        stream::{SplitSink, StreamExt},
    },
    log,
    protobuf::{Message as _, MessageField},
    rendezvous_proto::{
        register_pk_response::Result::{TOO_FREQUENT, UUID_MISMATCH},
        *,
    },
    tcp::FramedStream,
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{mpsc, Mutex},
        time::{interval, Duration},
    },
    tokio_util::codec::Framed,
    try_into_v4,
    udp::FramedSocket,
    AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use sodiumoxide::crypto::sign;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::Arc,
    time::Instant,
};

#[derive(Clone, Debug)]
enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
    RelayServers0(String),
    RelayServers(RelayServers),
}

const REG_TIMEOUT: i64 = 30_000;
type TcpStreamSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
type WsSink = SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, tungstenite::Message>;

enum Sink {
    // Rendezvous encryption: the connection's encryption once the key exchange succeeded.
    TcpStream(TcpStreamSink, Option<crate::rendezvous_kx::Shared>),
    // Rendezvous encryption: the same exchange runs inside the WebSocket.
    Ws(WsSink, Option<crate::rendezvous_kx::Shared>),
}
type Sender = mpsc::UnboundedSender<Data>;
type Receiver = mpsc::UnboundedReceiver<Data>;
static ROTATION_RELAY_SERVER: AtomicUsize = AtomicUsize::new(0);
type RelayServers = Vec<String>;
const CHECK_RELAY_TIMEOUT: u64 = 3_000;
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);
const MAX_RELAY_UUID_LEN: usize = 128;

// The peer sends this uuid to whatever relay_server names, so keep control bytes out of it.
fn validate_relay_uuid(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > MAX_RELAY_UUID_LEN
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("Invalid relay UUID");
    }
    Ok(())
}

// A peer acknowledging a RequestRelay leaves both fields empty.
fn validate_relay_response(uuid: &str, relay_server: &str) -> Result<(), &'static str> {
    if uuid.is_empty() && relay_server.is_empty() {
        return Ok(());
    }
    validate_relay_uuid(uuid)
}

// An online query for about 5000 ids is the largest message a client sends here.
const DEFAULT_MAX_MESSAGE_KB: usize = 64;
// A knob that can be turned to unbounded is not a bound.
const MAX_MESSAGE_KB_CAP: usize = 64 << 10;
// tungstenite's default, so raising MAX_MESSAGE_KB does not widen a frame past it.
const WS_DEFAULT_MAX_FRAME_SIZE: usize = 16 << 20;
// Every connection pays its read buffer up front, and tungstenite's default is 128 KiB.
const WS_BUFFER_SIZE: usize = 8 << 10;
static MAX_MESSAGE: Lazy<usize> =
    Lazy::new(|| max_message_kb(&get_arg("MAX_MESSAGE_KB")) << 10);

fn max_message_kb(arg: &str) -> usize {
    match arg.parse::<usize>() {
        Ok(kb) if kb > 0 => kb.min(MAX_MESSAGE_KB_CAP),
        _ => DEFAULT_MAX_MESSAGE_KB,
    }
}

// Store punch hole requests
use once_cell::sync::Lazy;
use tokio::sync::Mutex as TokioMutex; // differentiate if needed
#[derive(Clone)]
struct PunchReqEntry { tm: Instant, from_ip: String, to_ip: String, to_id: String }
static PUNCH_REQS: Lazy<TokioMutex<VecDeque<PunchReqEntry>>> = Lazy::new(|| TokioMutex::new(VecDeque::new()));
const PUNCH_REQ_DEDUPE_SEC: u64 = 60;
static PUNCH_REQ_MAX: Lazy<usize> =
    Lazy::new(|| get_arg("MAX_PUNCH_REQUESTS").parse().unwrap_or(100_000));
// HBB-01: one turn at a time at each stored connection (Turn), for send_to_tcp_keep and everything
// else that takes a connection out of tcp_punch, while sends to others go on. Each entry counts
// the turns held or waited for; the last one done removes it.
static KEEP_SENDS: Lazy<std::sync::Mutex<HashMap<SocketAddr, (Arc<Mutex<()>>, usize)>>> =
    Lazy::new(Default::default);

/// HBB-01: a turn at the connection stored for one address (KEEP_SENDS). Taken before tcp_punch is
/// locked, never while it is.
struct Turn {
    addr: SocketAddr,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Turn {
    async fn take(addr: SocketAddr) -> Turn {
        let lock = {
            let mut turns = KEEP_SENDS.lock().unwrap();
            let (lock, count) = turns.entry(addr).or_default();
            *count += 1;
            lock.clone()
        };
        // Counted before the wait, so a wait given up (its future dropped) is uncounted in drop.
        let mut turn = Turn { addr, guard: None };
        turn.guard = Some(lock.lock_owned().await);
        turn
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        self.guard.take();
        let mut turns = KEEP_SENDS.lock().unwrap();
        if let Some((_, count)) = turns.get_mut(&self.addr) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                turns.remove(&self.addr);
            }
        }
    }
}

// Managed hardening: relay tickets (relay_ticket.rs). What hbbs learned of a controller's request, by the
// controller's address, for the ticket it mints when the controlled side answers: the uuid (from a
// RequestRelay; on a punch request the controlled side picks it) and both ids. Only a proven
// device's requests that hbbs passed on are kept: at most RELAY_PENDING_PER_SOURCE from one source
// and RELAY_PENDING_MAX in all, the oldest making room, so a flood can't keep others' out.
struct RelayPending {
    uuid: String,
    controller_id: String,
    target_id: String,
    at: Instant,
    /// Its place in RelayPendings::order.
    seq: u64,
}
struct RelayPendings {
    map: HashMap<SocketAddr, RelayPending>,
    /// The keys of `map`, oldest first.
    order: BTreeMap<u64, SocketAddr>,
    /// The seqs of `map`'s entries by source (pending_source).
    by_source: HashMap<IpAddr, BTreeSet<u64>>,
    next: u64,
    max: usize,
    per_source: usize,
}
static RELAY_PENDING: Lazy<std::sync::Mutex<RelayPendings>> = Lazy::new(|| {
    std::sync::Mutex::new(RelayPendings::new(RELAY_PENDING_MAX, RELAY_PENDING_PER_SOURCE))
});
const RELAY_PENDING_MAX: usize = 16_384;
const RELAY_PENDING_PER_SOURCE: usize = 64;

/// Where a request came from, for RELAY_PENDING_PER_SOURCE: its IPv4 address, or its IPv6 /64 (a
/// host there can use every address in it).
fn pending_source(addr: SocketAddr) -> IpAddr {
    match try_into_v4(addr).ip() {
        IpAddr::V6(ip) => {
            let s = ip.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        ip => ip,
    }
}

impl RelayPendings {
    fn new(max: usize, per_source: usize) -> Self {
        RelayPendings {
            map: HashMap::new(),
            order: BTreeMap::new(),
            by_source: HashMap::new(),
            next: 0,
            max,
            per_source,
        }
    }

    fn expired(pending: &RelayPending, now: Instant) -> bool {
        now.saturating_duration_since(pending.at).as_secs() >= crate::relay_ticket::TTL_SECS
    }

    fn remove(&mut self, controller: SocketAddr) -> Option<RelayPending> {
        let pending = self.map.remove(&controller)?;
        self.order.remove(&pending.seq);
        let source = pending_source(controller);
        if let Some(seqs) = self.by_source.get_mut(&source) {
            seqs.remove(&pending.seq);
            if seqs.is_empty() {
                self.by_source.remove(&source);
            }
        }
        Some(pending)
    }

    /// Drops what expired by `now`, oldest first.
    fn prune(&mut self, now: Instant) {
        while let Some((&seq, &controller)) = self.order.first_key_value() {
            if !self.map.get(&controller).map_or(true, |p| Self::expired(p, now)) {
                break;
            }
            if self.remove(controller).is_none() {
                self.order.remove(&seq);
            }
        }
    }

    /// Keeps `pending` for `controller`, in place of what it had, making room first: the oldest
    /// from the same source when that has its share, the oldest of all when full.
    fn insert(&mut self, controller: SocketAddr, mut pending: RelayPending, now: Instant) {
        self.prune(now);
        let controller = try_into_v4(controller);
        self.remove(controller);
        let source = pending_source(controller);
        let oldest_of_source = self
            .by_source
            .get(&source)
            .filter(|seqs| seqs.len() >= self.per_source)
            .and_then(|seqs| seqs.first())
            .and_then(|seq| self.order.get(seq))
            .copied();
        if let Some(oldest) = oldest_of_source {
            self.remove(oldest);
        }
        if self.map.len() >= self.max {
            if let Some((_, &oldest)) = self.order.first_key_value() {
                self.remove(oldest);
            }
        }
        pending.at = now;
        pending.seq = self.next;
        self.next += 1;
        self.order.insert(pending.seq, controller);
        self.by_source.entry(source).or_default().insert(pending.seq);
        self.map.insert(controller, pending);
    }

    /// What `f` makes of the request kept for `controller`; the request is used up when `f` makes
    /// something of it, else it stays for another answer.
    fn take<T>(
        &mut self,
        controller: SocketAddr,
        now: Instant,
        f: impl FnOnce(&RelayPending) -> Option<T>,
    ) -> Option<T> {
        self.prune(now);
        let controller = try_into_v4(controller);
        let made = self.map.get(&controller).filter(|p| !Self::expired(p, now)).and_then(f)?;
        self.remove(controller);
        Some(made)
    }
}

/// Keeps a request a proven controller made of `target_id` that hbbs passed on, for the tickets of
/// the relay the answer may set up.
fn note_relay_pending(controller: SocketAddr, uuid: &str, controller_id: &str, target_id: &str) {
    use crate::relay_ticket::{minting_key, MAX_ID, MAX_UUID};
    if minting_key().is_none() {
        return;
    }
    let fit = |s: &str, max: usize| if s.len() <= max { s.to_owned() } else { String::new() };
    let pending = RelayPending {
        uuid: fit(uuid, MAX_UUID),
        controller_id: fit(controller_id, MAX_ID),
        target_id: fit(target_id, MAX_ID),
        at: Instant::now(),
        seq: 0,
    };
    RELAY_PENDING.lock().unwrap().insert(controller, pending, Instant::now());
}

/// Sets the controller's ticket on a RelayResponse a controlled device sent for `controller`, and
/// returns the controlled side's when it picked the uuid itself (else ""): it had no RequestRelay
/// to bring one. Only a connection that proved which device it is gets tickets, answering a request
/// hbbs passed on to that device from `controller` (answer_subject).
fn relay_response_tickets(
    rr: &mut RelayResponse,
    controller: SocketAddr,
    auth: &crate::device_auth::ConnAuth,
) -> String {
    use crate::relay_ticket::{mint_now, Role};
    rr.relay_ticket = String::new();
    let device_id = auth.device.as_ref().map(|d| d.id.as_str());
    let subject = answer_subject(
        &mut RELAY_PENDING.lock().unwrap(),
        rr,
        controller,
        device_id,
        Instant::now(),
    );
    let Some(subject) = subject else {
        return String::new();
    };
    rr.relay_ticket = mint_now(
        Role::Controller,
        &subject.uuid,
        &subject.controller_id,
        &subject.controlled_id,
    );
    if subject.reply {
        mint_now(Role::Controlled, &subject.uuid, &subject.controller_id, &subject.controlled_id)
    } else {
        String::new()
    }
}

/// What the tickets for a RelayResponse to `controller` from the device `device_id` (None: its
/// connection proved none) are for, using up the request kept for `controller`. None, with the
/// request left for the device's own answer, when they're for nothing.
fn answer_subject(
    pendings: &mut RelayPendings,
    rr: &RelayResponse,
    controller: SocketAddr,
    device_id: Option<&str>,
    now: Instant,
) -> Option<TicketSubject> {
    let device_id = device_id?;
    pendings.take(controller, now, |p| relay_ticket_subject(rr, p, device_id))
}

#[derive(Debug, PartialEq)]
struct TicketSubject {
    uuid: String,
    controller_id: String,
    controlled_id: String,
    /// The controlled side picked the uuid, so its ticket goes back to it.
    reply: bool,
}

/// What a RelayResponse's tickets are for, answering the request `pending`. The controlled side is
/// the device its connection proved to be (`device_id`), which must be the one the controller
/// asked for. The uuid is its own when it picked one (it started the relay), else the one the
/// controller's RequestRelay named; where both have one they must agree.
fn relay_ticket_subject(
    rr: &RelayResponse,
    pending: &RelayPending,
    device_id: &str,
) -> Option<TicketSubject> {
    if device_id.is_empty() || device_id != pending.target_id {
        return None;
    }
    let uuid = match (rr.uuid.as_str(), pending.uuid.as_str()) {
        ("", "") => return None,
        (uuid, "") | ("", uuid) => uuid,
        (ours, asked) if ours == asked => ours,
        _ => return None,
    };
    Some(TicketSubject {
        uuid: uuid.to_owned(),
        controller_id: pending.controller_id.clone(),
        controlled_id: device_id.to_owned(),
        reply: !rr.uuid.is_empty(),
    })
}

async fn record_punch_req(from_ip: String, to_ip: String, to_id: String) {
    let max = *PUNCH_REQ_MAX;
    if max == 0 { return; }
    let mut lock = PUNCH_REQS.lock().await;
    let mut dup = false;
    for e in lock.iter().rev().take(30) { // only check recent tail subset for speed
        if e.from_ip == from_ip && e.to_id == to_id {
            if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC { dup = true; }
            break;
        }
    }
    if !dup {
        if lock.len() >= max { lock.pop_front(); }
        lock.push_back(PunchReqEntry { tm: Instant::now(), from_ip, to_ip, to_id });
    }
}

#[derive(Clone)]
struct Inner {
    serial: i32,
    version: String,
    software_url: String,
    mask: Option<Ipv4Network>,
    local_ip: String,
    sk: Option<sign::SecretKey>,
}

#[derive(Clone)]
pub struct RendezvousServer {
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, Sink>>>,
    pm: PeerMap,
    tx: Sender,
    relay_servers: Arc<RelayServers>,
    relay_servers0: Arc<RelayServers>,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
}

enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
    ConsoleListener,
}

impl RendezvousServer {
    pub fn start(port: i32, serial: i32, key: &str, rmem: usize) -> ResultType<()> {
        Self::start_with_bind(None, port, serial, key, rmem)
    }

    #[tokio::main(flavor = "multi_thread")]
    pub async fn start_with_bind(
        bind_addr: Option<IpAddr>,
        port: i32,
        serial: i32,
        key: &str,
        rmem: usize,
    ) -> ResultType<()> {
        let (key, sk) = Self::get_server_sk(key)?;
        let nat_port = port - 1;
        let ws_port = port + 2;
        let ws_bind_addr = ws_bind_address(bind_addr)?;
        let pm = PeerMap::new().await?;
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers");
        let mut socket = create_udp_listener(bind_addr, port, rmem).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Data>();
        let software_url = get_arg("software-url");
        let version = hbb_common::get_version_from_url(&software_url);
        if !version.is_empty() {
            log::info!("software_url: {}, version: {}", software_url, version);
        }
        let mask = get_arg("mask").parse().ok();
        let local_ip = if mask.is_none() {
            "".to_owned()
        } else {
            get_arg_or(
                "local-ip",
                local_ip_address::local_ip()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            )
        };
        let mut rs = Self {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            pm,
            tx: tx.clone(),
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Arc::new(rendezvous_servers),
            inner: Arc::new(Inner {
                serial,
                version,
                software_url,
                sk,
                mask,
                local_ip,
            }),
        };
        log::info!("mask: {:?}", rs.inner.mask);
        log::info!("local-ip: {:?}", rs.inner.local_ip);
        std::env::set_var("PORT_FOR_API", port.to_string());
        rs.parse_relay_servers(&get_arg("relay-servers"));
        let mut listener = create_tcp_listener(bind_addr, port).await?;
        let mut listener2 = create_tcp_listener(bind_addr, nat_port).await?;
        let mut listener3 = create_tcp_listener(ws_bind_addr, ws_port).await?;
        let mut listener_console = listen_console(bind_addr, nat_port as _).await?;
        log::info!("Listening on tcp/udp {}", listener.local_addr()?);
        log::info!(
            "Listening on tcp {}, extra port for NAT test",
            listener2.local_addr()?
        );
        log::info!("Listening on websocket {}", listener3.local_addr()?);
        log::info!("MAX_MESSAGE_KB={}", *MAX_MESSAGE >> 10);
        let test_addr = get_arg("TEST_HBBS");
        if get_arg("ALWAYS_USE_RELAY").to_uppercase() == "Y" {
            ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        }
        log::info!(
            "ALWAYS_USE_RELAY={}",
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        crate::approved_gate::mode();
        crate::rendezvous_kx::spawn_report();
        crate::device_auth::spawn_report();
        crate::webrtc_signal::enabled_for("");
        let _ = crate::relay_ticket::minting_key();
        if test_addr.to_lowercase() != "no" {
            let test_addr = if test_addr.is_empty() {
                listener.local_addr()?
            } else {
                test_addr.parse()?
            };
            tokio::spawn(async move {
                if let Err(err) = test_hbbs(test_addr).await {
                    if test_addr.is_ipv6() && test_addr.ip().is_unspecified() {
                        let mut test_addr = test_addr;
                        test_addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                        if let Err(err) = test_hbbs(test_addr).await {
                            log::error!("Failed to run hbbs test with {test_addr}: {err}");
                            std::process::exit(1);
                        }
                    } else {
                        log::error!("Failed to run hbbs test with {test_addr}: {err}");
                        std::process::exit(1);
                    }
                }
            });
        };
        let main_task = async move {
            loop {
                log::info!("Start");
                match rs
                    .io_loop(
                        &mut rx,
                        &mut listener,
                        &mut listener2,
                        &mut listener3,
                        &mut listener_console,
                        &mut socket,
                        &key,
                    )
                    .await
                {
                    LoopFailure::UdpSocket => {
                        drop(socket);
                        socket = create_udp_listener(bind_addr, port, rmem).await?;
                    }
                    LoopFailure::Listener => {
                        drop(listener);
                        listener = create_tcp_listener(bind_addr, port).await?;
                    }
                    LoopFailure::Listener2 => {
                        drop(listener2);
                        listener2 = create_tcp_listener(bind_addr, nat_port).await?;
                    }
                    LoopFailure::ConsoleListener => {
                        drop(listener_console.take());
                        listener_console = listen_console(bind_addr, nat_port as _).await?;
                    }
                    LoopFailure::Listener3 => {
                        drop(listener3);
                        listener3 = create_tcp_listener(ws_bind_addr, ws_port).await?;
                    }
                }
            }
        };
        let listen_signal = listen_signal();
        tokio::select!(
            res = main_task => res,
            res = listen_signal => res,
        )
    }

    async fn io_loop(
        &mut self,
        rx: &mut Receiver,
        listener: &mut TcpListener,
        listener2: &mut TcpListener,
        listener3: &mut TcpListener,
        listener_console: &mut Option<TcpListener>,
        socket: &mut FramedSocket,
        key: &str,
    ) -> LoopFailure {
        let mut timer_check_relay = interval(Duration::from_millis(CHECK_RELAY_TIMEOUT));
        loop {
            tokio::select! {
                _ = timer_check_relay.tick() => {
                    if self.relay_servers0.len() > 1 {
                        let rs = self.relay_servers0.clone();
                        let tx = self.tx.clone();
                        tokio::spawn(async move {
                            check_relay_servers(rs, tx).await;
                        });
                    }
                }
                Some(data) = rx.recv() => {
                    match data {
                        Data::Msg(msg, addr) => { allow_err!(socket.send(msg.as_ref(), addr).await); }
                        Data::RelayServers0(rs) => { self.parse_relay_servers(&rs); }
                        Data::RelayServers(rs) => { self.relay_servers = Arc::new(rs); }
                    }
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            if let Err(err) = self.handle_udp(&bytes, addr.into(), socket, key).await {
                                log::error!("udp failure: {}", err);
                                return LoopFailure::UdpSocket;
                            }
                        }
                        Some(Err(err)) => {
                            log::error!("udp failure: {}", err);
                            return LoopFailure::UdpSocket;
                        }
                        None => {
                            // unreachable!() ?
                        }
                    }
                }
                res = listener2.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("listener2.accept failed: {}", err);
                           return LoopFailure::Listener2;
                        }
                    }
                }
                res = accept_or_pending(listener_console.as_ref()) => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("console listener.accept failed: {}", err);
                           return LoopFailure::ConsoleListener;
                        }
                    }
                }
                res = listener3.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, true).await;
                        }
                        Err(err) => {
                           log::error!("listener3.accept failed: {}", err);
                           return LoopFailure::Listener3;
                        }
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, false).await;
                        }
                       Err(err) => {
                           log::error!("listener.accept failed: {}", err);
                           return LoopFailure::Listener;
                       }
                    }
                }
            }
        }
    }

    #[inline]
    async fn handle_udp(
        &mut self,
        bytes: &BytesMut,
        addr: SocketAddr,
        socket: &mut FramedSocket,
        key: &str,
    ) -> ResultType<()> {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // B registered
                    if !rp.id.is_empty() && rp.id.len() <= MAX_PEER_ID_LEN {
                        log::trace!("New peer registered: {:?} {:?}", &rp.id, &addr);
                        self.update_addr(rp.id, addr, socket).await?;
                        if self.inner.serial > rp.serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    if rk.uuid.is_empty() || rk.pk.is_empty() {
                        return Ok(());
                    }
                    let id = rk.id;
                    let ip = addr.ip().to_string();
                    if id.len() < 6 || id.len() > MAX_PEER_ID_LEN {
                        return send_rk_res(socket, addr, UUID_MISMATCH).await;
                    } else if !self.check_ip_blocker(&ip, &id).await {
                        return send_rk_res(socket, addr, TOO_FREQUENT).await;
                    }
                    let peer = self.pm.get_or(&id).await;
                    let (changed, ip_changed) = {
                        let peer = peer.read().await;
                        if peer.uuid.is_empty() {
                            (true, false)
                        } else {
                            if peer.uuid == rk.uuid {
                                if peer.info.ip != ip && peer.pk != rk.pk {
                                    log::warn!(
                                        "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                                        id,
                                        ip,
                                        rk.pk,
                                        peer.info.ip,
                                        peer.pk,
                                    );
                                    drop(peer);
                                    return send_rk_res(socket, addr, UUID_MISMATCH).await;
                                }
                            } else {
                                log::warn!(
                                    "Peer {} uuid mismatch: {:?} vs {:?}",
                                    id,
                                    rk.uuid,
                                    peer.uuid
                                );
                                drop(peer);
                                return send_rk_res(socket, addr, UUID_MISMATCH).await;
                            }
                            let ip_changed = peer.info.ip != ip;
                            (
                                peer.uuid != rk.uuid || peer.pk != rk.pk || ip_changed,
                                ip_changed,
                            )
                        }
                    };
                    let mut req_pk = peer.read().await.reg_pk;
                    if req_pk.1.elapsed().as_secs() > 6 {
                        req_pk.0 = 0;
                    } else if req_pk.0 > 2 {
                        return send_rk_res(socket, addr, TOO_FREQUENT).await;
                    }
                    req_pk.0 += 1;
                    req_pk.1 = Instant::now();
                    peer.write().await.reg_pk = req_pk;
                    if ip_changed {
                        let mut lock = IP_CHANGES.lock().await;
                        if let Some((tm, ips)) = lock.get_mut(&id) {
                            if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                                *tm = Instant::now();
                                ips.clear();
                                ips.insert(ip.clone(), 1);
                            } else if let Some(v) = ips.get_mut(&ip) {
                                *v += 1;
                            } else {
                                ips.insert(ip.clone(), 1);
                            }
                        } else {
                            lock.insert(
                                id.clone(),
                                (Instant::now(), HashMap::from([(ip.clone(), 1)])),
                            );
                        }
                    }
                    if changed {
                        self.pm.update_pk(id, peer, addr, rk.uuid, rk.pk, ip).await;
                    }
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: register_pk_response::Result::OK.into(),
                        ..Default::default()
                    });
                    socket.send(&msg_out, addr).await?
                }
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // UDP PunchHoleRequest is intentionally unsupported.
                    // The supported client path sends PunchHoleRequest over TCP/WS.
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    // UDP PunchHoleSent is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    // UDP LocalAddr is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::ConfigureUpdate(mut cu)) => {
                    if try_into_v4(addr).ip().is_loopback() && cu.serial > self.inner.serial {
                        let mut inner: Inner = (*self.inner).clone();
                        inner.serial = cu.serial;
                        self.inner = Arc::new(inner);
                        self.rendezvous_servers = Arc::new(
                            cu.rendezvous_servers
                                .drain(..)
                                .filter(|x| {
                                    !x.is_empty()
                                        && test_if_valid_server(x, "rendezvous-server").is_ok()
                                })
                                .collect(),
                        );
                        log::info!(
                            "configure updated: serial={} rendezvous-servers={:?}",
                            self.inner.serial,
                            self.rendezvous_servers
                        );
                    }
                }
                Some(rendezvous_message::Union::SoftwareUpdate(su)) => {
                    if !self.inner.version.is_empty() && su.url != self.inner.version {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_software_update(SoftwareUpdate {
                            url: self.inner.software_url.clone(),
                            ..Default::default()
                        });
                        socket.send(&msg_out, addr).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        key: &str,
        ws: bool,
        auth: &mut crate::device_auth::ConnAuth,
    ) -> bool {
        use crate::device_auth::{allows, Kind};
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                // Device passports: the device proves who it is for the rest of this connection.
                Some(rendezvous_message::Union::DeviceAuth(da)) => {
                    let server_pk = self.inner.sk.as_ref().map(|sk| sk.0[32..].to_vec()).unwrap_or_default();
                    crate::device_auth::authenticate(auth, &da, &server_pk, addr);
                    return true;
                }
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    if !allows(auth, Kind::Request, "", &ph.id, addr) {
                        return false;
                    }
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    // Managed hardening: a proven controller's request is kept for the relay tickets, once
                    // passed on (handle_tcp_punch_hole_request).
                    let controller_id = auth.device.as_ref().map(|d| d.id.as_str());
                    allow_err!(
                        self.handle_tcp_punch_hole_request(addr, ph, key, ws, controller_id).await
                    );
                    return true;
                }
                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                    if !allows(auth, Kind::Request, "", &rf.id, addr) {
                        return false;
                    }
                    if let Err(err) = validate_relay_uuid(&rf.uuid) {
                        log::warn!(
                            "Drop RequestRelay from {addr}: {err} (length {})",
                            rf.uuid.len()
                        );
                        return false;
                    }
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    if !self.approved_gate_allows(addr, &rf.id, "relay").await {
                        return true;
                    }
                    if let Some(peer) = self.pm.get_in_memory(&rf.id).await {
                        let mut msg_out = RendezvousMessage::new();
                        rf.socket_addr = AddrMangle::encode(addr).into();
                        // RDC-03: hbbs issues neither (PunchHole and FetchLocalAddr are built
                        // afresh), so these could only be the controller's say over the
                        // controlled side's permissions.
                        rf.control_permissions = MessageField::none();
                        rf.controlled_context = MessageField::none();
                        // Managed hardening: the controlled side's relay ticket, only for a controller that
                        // proved which device it is (the ticket names it); the controller's goes
                        // with the answer (relay_response_tickets).
                        rf.relay_ticket = String::new();
                        if let Some(device) = auth.device.as_ref() {
                            rf.relay_ticket = crate::relay_ticket::mint_now(
                                crate::relay_ticket::Role::Controlled,
                                &rf.uuid,
                                &device.id,
                                &rf.id,
                            );
                            // No ticket (no key, no usable uuid): the answer can't get one either.
                            if !rf.relay_ticket.is_empty() {
                                note_relay_pending(addr, &rf.uuid, &device.id, &rf.id);
                            }
                        }
                        msg_out.set_request_relay(rf);
                        let peer_addr = peer.read().await.socket_addr;
                        self.tx.send(Data::Msg(msg_out.into(), peer_addr)).ok();
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                    if !allows(auth, Kind::Reply, rr.id(), "", addr) {
                        return false;
                    }
                    if let Err(err) = validate_relay_response(&rr.uuid, &rr.relay_server) {
                        log::warn!(
                            "Drop RelayResponse from {addr}: {err} (length {})",
                            rr.uuid.len()
                        );
                        return false;
                    }
                    let addr_b = AddrMangle::decode(&rr.socket_addr);
                    rr.socket_addr = Default::default();
                    // Managed hardening: relay tickets, for a proven device answering a request passed on
                    // to it; a controlled side that picked the uuid gets its own back on this
                    // connection.
                    let ticket = relay_response_tickets(&mut rr, addr_b, auth);
                    if !ticket.is_empty() {
                        let mut reply = RendezvousMessage::new();
                        reply.set_relay_response(RelayResponse {
                            uuid: rr.uuid.clone(),
                            relay_ticket: ticket,
                            ..Default::default()
                        });
                        timeout(1_000, Self::send_to_sink(sink, reply)).await.ok();
                    }
                    let id = rr.id();
                    if !id.is_empty() {
                        let pk = self.get_pk(&rr.version, id.to_owned()).await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    if !rr.relay_server.is_empty() {
                        if self.is_lan(addr_b) {
                            // https://github.com/rustdesk/rustdesk-server/issues/24
                            rr.relay_server = self.inner.local_ip.clone();
                        } else if rr.relay_server == self.inner.local_ip {
                            rr.relay_server = self.get_relay_server(addr.ip(), addr_b.ip());
                        }
                    }
                    // WebRTC signaling: a WebRTC answer rides along; keep the controller's connection then.
                    if crate::webrtc_signal::is_open(addr_b) {
                        msg_out.set_relay_response(rr);
                        self.send_to_tcp_keep(msg_out, addr_b).await;
                    } else {
                        rr.webrtc_sdp_answer = Default::default();
                        msg_out.set_relay_response(rr);
                        allow_err!(self.send_to_tcp_sync(msg_out, addr_b).await);
                    }
                }
                Some(rendezvous_message::Union::IceCandidate(ice)) => {
                    use crate::webrtc_signal::{route, Route};
                    // Managed hardening: a candidate naming the controller must come from the session's
                    // target, proven by its passport (see webrtc_signal::route).
                    let proven_id = auth.device.as_ref().map(|d| d.id.as_str());
                    match route(addr, &ice, proven_id, crate::device_auth::mode()) {
                        Route::ToTarget(target) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_ice_candidate(ice);
                            self.tx.send(Data::Msg(msg_out.into(), target)).ok();
                        }
                        Route::ToController(controller) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_ice_candidate(ice);
                            self.send_to_tcp_keep(msg_out, controller).await;
                        }
                        Route::Drop(why) => {
                            log::debug!("ICE candidate from {:?} dropped: {}", addr, why);
                            return false;
                        }
                    }
                    return true;
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    if !allows(auth, Kind::Reply, &phs.id, "", addr) {
                        return false;
                    }
                    allow_err!(self.handle_hole_sent(phs, addr, None).await);
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    if !allows(auth, Kind::Reply, &la.id, "", addr) {
                        return false;
                    }
                    allow_err!(self.handle_local_addr(la, addr, None).await);
                }
                Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                    let mut msg_out = RendezvousMessage::new();
                    let mut res = TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    };
                    if self.inner.serial > tar.serial {
                        let mut cu = ConfigUpdate::new();
                        cu.serial = self.inner.serial;
                        cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                        res.cu = MessageField::from_option(Some(cu));
                    }
                    msg_out.set_test_nat_response(res);
                    Self::send_to_sink(sink, msg_out).await;
                }
                Some(rendezvous_message::Union::RegisterPk(_)) => {
                    let res = register_pk_response::Result::NOT_SUPPORT;
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: res.into(),
                        ..Default::default()
                    });
                    Self::send_to_sink(sink, msg_out).await;
                }
                // Online status: online states here too, so clients can ask over their key-exchanged
                // connection (and its WebSocket fallback) instead of the separate NAT-test port,
                // which some networks block.
                // Only approved devices get an answer: the request names the asking device's own
                // id, which must be on the RDS-approved list. Anyone else gets nothing, so this
                // can't be used to probe which ids exist; an unavailable list refuses everyone,
                // which only empties the online marks.
                Some(rendezvous_message::Union::OnlineRequest(or)) => {
                    if !allows(auth, Kind::Online, &or.id, "", addr) {
                        return false;
                    }
                    match crate::approved_gate::approved_ids() {
                        Some(ids) if ids.contains(&or.id) => {
                            let msg_out = self.online_response(or.peers).await;
                            Self::send_to_sink(sink, msg_out).await;
                            // Online status: keep the connection for the client's next query (managed
                            // clients reuse it while their peer list is open); idle ones still end
                            // after the 30 s read timeout.
                            return true;
                        }
                        Some(_) => log::debug!(
                            "online request from {:?} as {:?} refused: not an approved id",
                            addr,
                            or.id
                        ),
                        None => log::warn!(
                            "online request from {:?} refused: the approved id list is unavailable",
                            addr
                        ),
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// The OnlineResponse for `peers`, as handle_online_request builds it.
    async fn online_response(&mut self, peers: Vec<String>) -> RendezvousMessage {
        let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i64;
                if elapsed < REG_TIMEOUT {
                    states[i / 8] |= 0x01 << (7 - i % 8);
                }
            }
        }
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        msg_out
    }

    #[inline]
    async fn update_addr(
        &mut self,
        id: String,
        socket_addr: SocketAddr,
        socket: &mut FramedSocket,
    ) -> ResultType<()> {
        let (request_pk, ip_change) = if let Some(old) = self.pm.get_in_memory(&id).await {
            let mut old = old.write().await;
            let ip = socket_addr.ip();
            let ip_change = if old.socket_addr.port() != 0 {
                ip != old.socket_addr.ip()
            } else {
                ip.to_string() != old.info.ip
            } && !ip.is_loopback();
            let request_pk = old.pk.is_empty() || ip_change;
            if !request_pk {
                old.socket_addr = socket_addr;
                old.last_reg_time = Instant::now();
            }
            let ip_change = if ip_change && old.reg_pk.0 <= 2 {
                Some(if old.socket_addr.port() == 0 {
                    old.info.ip.clone()
                } else {
                    old.socket_addr.to_string()
                })
            } else {
                None
            };
            (request_pk, ip_change)
        } else {
            (true, None)
        };
        if let Some(old) = ip_change {
            log::info!("IP change of {} from {} to {}", id, old, socket_addr);
        }
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_peer_response(RegisterPeerResponse {
            request_pk,
            ..Default::default()
        });
        socket.send(&msg_out, socket_addr).await
    }

    #[inline]
    async fn handle_hole_sent<'a>(
        &mut self,
        phs: PunchHoleSent,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // punch hole sent from B, tell A that B is ready to be connected
        let addr_a = AddrMangle::decode(&phs.socket_addr);
        log::debug!(
            "{} punch hole response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: AddrMangle::encode(addr).into(),
            pk: self.get_pk(&phs.version, phs.id).await,
            relay_server: phs.relay_server.clone(),
            ..Default::default()
        };
        if let Ok(t) = phs.nat_type.enum_value() {
            p.set_nat_type(t);
        }
        // WebRTC signaling: the WebRTC answer, and the controller's connection kept for the candidates.
        let webrtc = socket.is_none() && crate::webrtc_signal::is_open(addr_a);
        if webrtc {
            p.webrtc_sdp_answer = phs.webrtc_sdp_answer;
        }
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else if webrtc {
            self.send_to_tcp_keep(msg_out, addr_a).await;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_local_addr<'a>(
        &mut self,
        la: LocalAddr,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // relay local addrs of B to A
        let addr_a = AddrMangle::decode(&la.socket_addr);
        log::debug!(
            "{} local addrs response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: la.local_addr.clone(),
            pk: self.get_pk(&la.version, la.id).await,
            relay_server: la.relay_server,
            ..Default::default()
        };
        p.set_is_local(true);
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    /// Approved-device gate: whether a connection request from `addr` may proceed (see approved_gate).
    async fn approved_gate_allows(&self, addr: SocketAddr, target: &str, kind: &str) -> bool {
        use crate::approved_gate::{approved_ids, mode, Mode};
        let mode = mode();
        if mode == Mode::Off {
            return true;
        }
        let Some(ids) = approved_ids() else {
            return true;
        };
        let ip = try_into_v4(addr).ip();
        for id in ids.iter() {
            if let Some(peer) = self.pm.get_in_memory(id).await {
                let peer = peer.read().await;
                if try_into_v4(peer.socket_addr).ip() == ip
                    && (peer.last_reg_time.elapsed().as_millis() as i64) < REG_TIMEOUT
                {
                    log::info!("approved-gate: {} request from {} ({}) to {} allowed", kind, ip, id, target);
                    return true;
                }
            }
        }
        if mode == Mode::Enforce {
            log::warn!("approved-gate: {} request from {} to {} blocked - not an approved device's address", kind, ip, target);
            false
        } else {
            log::warn!("approved-gate: {} request from {} to {} would be blocked - not an approved device's address", kind, ip, target);
            true
        }
    }

    #[inline]
    async fn handle_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<(RendezvousMessage, Option<SocketAddr>)> {
        let mut ph = ph;
        if !key.is_empty() && ph.licence_key != key {
            log::warn!("Authentication failed from {} for peer {} - invalid key", addr, ph.id);
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        if !self.approved_gate_allows(addr, &ph.id, "punch").await {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        let id = ph.id;
        // punch hole request from A, relay to B,
        // check if in same intranet first,
        // fetch local addrs if in same intranet.
        // because punch hole won't work if in the same intranet,
        // all routers will drop such self-connections.
        if let Some(peer) = self.pm.get(&id).await {
            let (elapsed, peer_addr) = {
                let r = peer.read().await;
                (r.last_reg_time.elapsed().as_millis() as i64, r.socket_addr)
            };
            if elapsed >= REG_TIMEOUT {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }
            
            // record punch hole request (from addr -> peer id/peer_addr)
            record_punch_req(
                try_into_v4(addr).ip().to_string(),
                try_into_v4(peer_addr).ip().to_string(),
                id.clone(),
            )
            .await;

            let mut msg_out = RendezvousMessage::new();
            let peer_is_lan = self.is_lan(peer_addr);
            let is_lan = self.is_lan(addr);
            let mut relay_server = self.get_relay_server(addr.ip(), peer_addr.ip());
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) || (peer_is_lan ^ is_lan) {
                if peer_is_lan {
                    // https://github.com/rustdesk/rustdesk-server/issues/24
                    relay_server = self.inner.local_ip.clone()
                }
                ph.nat_type = NatType::SYMMETRIC.into(); // will force relay
            }
            let same_intranet: bool = !ws
                && (peer_is_lan && is_lan || {
                    match (peer_addr, addr) {
                        (SocketAddr::V4(a), SocketAddr::V4(b)) => a.ip() == b.ip(),
                        (SocketAddr::V6(a), SocketAddr::V6(b)) => a.ip() == b.ip(),
                        _ => false,
                    }
                });
            let socket_addr = AddrMangle::encode(addr).into();
            if same_intranet {
                log::debug!(
                    "Fetch local addr {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_fetch_local_addr(FetchLocalAddr {
                    socket_addr,
                    relay_server,
                    ..Default::default()
                });
            } else {
                log::debug!(
                    "Punch hole {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                // WebRTC signaling: the WebRTC offer goes through only inside a session (webrtc_signal).
                let mut webrtc_sdp_offer = String::new();
                // Not over WebSocket or UDP: hbbs can't keep those connections for the candidates.
                if !ws && !ph.webrtc_sdp_offer.is_empty() && crate::webrtc_signal::enabled_for(&id) {
                    let (opened, expired) = crate::webrtc_signal::open(addr, &id, peer_addr);
                    self.release_kept(expired).await;
                    if opened {
                        webrtc_sdp_offer = std::mem::take(&mut ph.webrtc_sdp_offer);
                    }
                }
                msg_out.set_punch_hole(PunchHole {
                    socket_addr,
                    nat_type: ph.nat_type,
                    relay_server,
                    webrtc_sdp_offer,
                    ..Default::default()
                });
            }
            Ok((msg_out, Some(peer_addr)))
        } else {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
        }
    }

    #[inline]
    async fn handle_online_request(
        &mut self,
        stream: &mut FramedStream,
        peers: Vec<String>,
    ) -> ResultType<()> {
        let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i64;
                // bytes index from left to right
                let states_idx = i / 8;
                let bit_idx = 7 - i % 8;
                if elapsed < REG_TIMEOUT {
                    states[states_idx] |= 0x01 << bit_idx;
                }
            }
        }

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        stream.send(&msg_out).await?;

        Ok(())
    }

    #[inline]
    async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        let mut tcp = self.take_sink(addr).await;
        tokio::spawn(async move {
            Self::send_to_sink(&mut tcp, msg).await;
        });
    }

    #[inline]
    async fn send_to_sink(sink: &mut Option<Sink>, msg: RendezvousMessage) {
        if let Some(sink) = sink.as_mut() {
            if let Ok(bytes) = msg.write_to_bytes() {
                match sink {
                    Sink::TcpStream(s, encrypt) => {
                        let bytes = match encrypt {
                            Some(encrypt) => encrypt.lock().unwrap().enc(&bytes),
                            None => bytes,
                        };
                        allow_err!(s.send(Bytes::from(bytes)).await);
                    }
                    Sink::Ws(ws, encrypt) => {
                        let bytes = match encrypt {
                            Some(encrypt) => encrypt.lock().unwrap().enc(&bytes),
                            None => bytes,
                        };
                        allow_err!(ws.send(tungstenite::Message::Binary(Bytes::from(bytes))).await);
                    }
                }
            }
        }
    }

    #[inline]
    async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let mut sink = self.take_sink(addr).await;
        Self::send_to_sink(&mut sink, msg).await;
        Ok(())
    }

    /// HBB-01: takes `addr`'s stored connection out of tcp_punch on its turn (Turn), so one a
    /// send_to_tcp_keep has out is taken once it's back, not missed.
    async fn take_sink(&self, addr: SocketAddr) -> Option<Sink> {
        let addr = try_into_v4(addr);
        let _turn = Turn::take(addr).await;
        self.tcp_punch.lock().await.remove(&addr)
    }

    /// WebRTC signaling: like send_to_tcp_sync, but the connection stays stored for more messages (a
    /// WebRTC session's answer and candidates); a send that times out drops it.
    /// HBB-01: the map is locked only to take the connection out and put it back, never across
    /// the send, so a stalled client holds up only its own messages. Everything that takes a
    /// connection out of the map does it on its turn at that connection (Turn), so messages go
    /// one at a time, in order: a candidate or a final answer arriving mid-send waits for the
    /// connection instead of finding it gone, and a connection that closed meanwhile is removed
    /// once it's back, not before (and so not put back after).
    async fn send_to_tcp_keep(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        let addr = try_into_v4(addr);
        let _turn = Turn::take(addr).await;
        let mut sink = self.tcp_punch.lock().await.remove(&addr);
        if timeout(3_000, Self::send_to_sink(&mut sink, msg)).await.is_ok() {
            if let Some(sink) = sink {
                // A newer connection stored meanwhile from this address wins.
                self.tcp_punch.lock().await.entry(addr).or_insert(sink);
            }
        }
    }

    /// WebRTC signaling: drops the connections kept for WebRTC sessions that expired.
    async fn release_kept(&mut self, controllers: Vec<SocketAddr>) {
        if controllers.is_empty() {
            return;
        }
        for addr in controllers {
            self.take_sink(addr).await;
        }
    }

    #[inline]
    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
        controller_id: Option<&str>,
    ) -> ResultType<()> {
        let target_id = ph.id.clone();
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, ws).await?;
        if let Some(peer_addr) = to_addr {
            // Managed hardening: passed on, so the device may answer with a relay; a proven controller's
            // request is kept for its tickets (relay_response_tickets).
            if let Some(controller_id) = controller_id {
                note_relay_pending(addr, "", controller_id, &target_id);
            }
            self.tx.send(Data::Msg(msg.into(), peer_addr))?;
        } else {
            self.send_to_tcp_sync(msg, addr).await?;
        }
        Ok(())
    }

    #[inline]
    async fn handle_udp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
    ) -> ResultType<()> {
        let mut ph = ph;
        ph.webrtc_sdp_offer = Default::default();
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, false).await?;
        self.tx.send(Data::Msg(
            msg.into(),
            match to_addr {
                Some(addr) => addr,
                None => addr,
            },
        ))?;
        Ok(())
    }

    async fn check_ip_blocker(&self, ip: &str, id: &str) -> bool {
        let mut lock = IP_BLOCKER.lock().await;
        let now = Instant::now();
        if let Some(old) = lock.get_mut(ip) {
            let counter = &mut old.0;
            if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
                counter.0 = 0;
            } else if counter.0 > 30 {
                return false;
            }
            counter.0 += 1;
            counter.1 = now;

            let counter = &mut old.1;
            let is_new = counter.0.get(id).is_none();
            if counter.1.elapsed().as_secs() > DAY_SECONDS {
                counter.0.clear();
            } else if counter.0.len() > 300 {
                return !is_new;
            }
            if is_new {
                counter.0.insert(id.to_owned());
            }
            counter.1 = now;
        } else {
            lock.insert(ip.to_owned(), ((0, now), (Default::default(), now)));
        }
        true
    }

    fn parse_relay_servers(&mut self, relay_servers: &str) {
        let rs = get_servers(relay_servers, "relay-servers");
        self.relay_servers0 = Arc::new(rs);
        self.relay_servers = self.relay_servers0.clone();
    }

    fn get_relay_server(&self, _pa: IpAddr, _pb: IpAddr) -> String {
        if self.relay_servers.is_empty() {
            return "".to_owned();
        } else if self.relay_servers.len() == 1 {
            return self.relay_servers[0].clone();
        }
        let i = ROTATION_RELAY_SERVER.fetch_add(1, Ordering::SeqCst) % self.relay_servers.len();
        self.relay_servers[i].clone()
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) <separated by ,>",
                    "reload-geo(rg)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur)",
                    "test-geo(tg) <ip1> <ip2>"
                )
            }
            Some("relay-servers" | "rs") => {
                if let Some(rs) = fds.next() {
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    for ip in self.relay_servers.iter() {
                        let _ = writeln!(res, "{ip}");
                    }
                }
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                lock.retain(|&_, (a, b)| {
                    a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                        || b.1.elapsed().as_secs() <= DAY_SECONDS
                });
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        if let Some((a, b)) = lock.get(ip) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if fds.next() == Some("-") {
                            lock.remove(ip);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((ip, (a, b))) = x {
                            let _ = writeln!(
                                res,
                                "{}: {}/{}s {}/{}s",
                                ip,
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                    }
                }
            }
            Some("ip-changes" | "ic") => {
                let mut lock = IP_CHANGES.lock().await;
                lock.retain(|&_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
                res = format!("{}\n", lock.len());
                let id = fds.next();
                let mut start = id.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if !(0..=10_000_000).contains(&start) {
                    if let Some(id) = id {
                        if let Some((tm, ips)) = lock.get(id) {
                            let _ = writeln!(res, "{}s {:?}", tm.elapsed().as_secs(), ips);
                        }
                        if fds.next() == Some("-") {
                            lock.remove(id);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((id, (tm, ips))) = x {
                            let _ = writeln!(res, "{}: {}s {:?}", id, tm.elapsed().as_secs(), ips,);
                        }
                    }
                }
            }
            Some("punch-requests" | "pr") => {
                use std::fmt::Write as _;
                let mut lock = PUNCH_REQS.lock().await;
                let arg = fds.next();
                if let Some("-") = arg { lock.clear(); }
                else {
                    let mut start = arg.and_then(|x| x.parse::<usize>().ok()).unwrap_or(0);
                    let mut page_size = fds.next().and_then(|x| x.parse::<usize>().ok()).unwrap_or(10);
                    if page_size == 0 { page_size = 10; }
                    for (_, e) in lock.iter().enumerate().skip(start).take(page_size) {
                        let age = e.tm.elapsed();
                        let event_system = std::time::SystemTime::now() - age;
                        let event_iso = chrono::DateTime::<chrono::Utc>::from(event_system)
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        let _ = writeln!(res, "{} {} -> {}@{}", event_iso, e.from_ip, e.to_id, e.to_ip);
                    }
                }
            }
            Some("always-use-relay" | "aur") => {
                if let Some(rs) = fds.next() {
                    if rs.to_uppercase() == "Y" {
                        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
                    } else {
                        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
                    }
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    let _ = writeln!(
                        res,
                        "ALWAYS_USE_RELAY: {:?}",
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                    );
                }
            }
            Some("test-geo" | "tg") => {
                if let Some(rs) = fds.next() {
                    if let Ok(a) = rs.parse::<IpAddr>() {
                        if let Some(rs) = fds.next() {
                            if let Ok(b) = rs.parse::<IpAddr>() {
                                res = format!("{:?}", self.get_relay_server(a, b));
                            }
                        } else {
                            res = format!("{:?}", self.get_relay_server(a, a));
                        }
                    }
                }
            }
            _ => {}
        }
        res
    }

    /// Handles loopback console requests and external NAT or online-status queries.
    async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let mut rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if ip.is_loopback() {
            tokio::spawn(async move {
                let mut stream = stream;
                let mut buffer = [0; 1024];
                if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                    if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                        let res = rs.check_cmd(data).await;
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
        let mut stream = FramedStream::from(stream, addr);
        stream.codec_mut().set_max_packet_length(*MAX_MESSAGE);
        tokio::spawn(async move {
            let mut stream = stream;
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or)) => {
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    async fn handle_listener(&self, stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    /// Processes rendezvous messages on an accepted TCP or WebSocket connection.
    #[inline]
    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        mut addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let mut sink;
        let mut auth = crate::device_auth::ConnAuth::default();
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
            let ws_config = tungstenite::protocol::WebSocketConfig::default()
                .max_message_size(Some(*MAX_MESSAGE))
                .max_frame_size(Some((*MAX_MESSAGE).min(WS_DEFAULT_MAX_FRAME_SIZE)))
                .read_buffer_size(WS_BUFFER_SIZE)
                .write_buffer_size(WS_BUFFER_SIZE);
            let ws_stream = timeout(
                30_000,
                tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(ws_config)),
            )
            .await??;
            let (mut a, mut b) = ws_stream.split();
            // Rendezvous encryption: key exchange first, as on TCP, so a client that fell back to WebSocket
            // doesn't depend on the TLS in front of it for the server's identity.
            let mut encrypt = None;
            let mut first = None;
            let kx = crate::rendezvous_kx::mode();
            let sk = self.inner.sk.as_ref().filter(|_| kx != crate::rendezvous_kx::Mode::Off);
            if let Some(sk) = sk {
                use crate::rendezvous_kx::{handshake, Mode, Outcome};
                use hbb_common::futures::future::ready;
                let mut kx_sink = (&mut a)
                    .sink_map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
                    .with(|bytes: Bytes| {
                        ready(Ok::<_, std::io::Error>(tungstenite::Message::Binary(bytes)))
                    });
                let mut kx_stream = (&mut b).filter_map(|msg| {
                    ready(match msg {
                        Ok(tungstenite::Message::Binary(bytes)) => Some(Ok(BytesMut::from(&bytes[..]))),
                        Ok(_) => None,
                        Err(e) => Some(Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        ))),
                    })
                });
                match handshake(&mut kx_sink, &mut kx_stream, sk, 30_000, kx).await {
                    Ok(Outcome::Secured(e, binding)) => {
                        encrypt = Some(e);
                        auth.binding = Some(binding);
                    }
                    Ok(Outcome::Plain(bytes)) if kx == Mode::Optional => first = Some(bytes),
                    Ok(Outcome::Plain(_)) => {
                        log::debug!("Ws connection from {:?} refused: no key exchange", addr);
                        return Ok(());
                    }
                    Ok(Outcome::Closed) => return Ok(()),
                    Err(err) => {
                        log::debug!("Key exchange with {:?} (ws) failed: {}", addr, err);
                        return Ok(());
                    }
                }
            }
            sink = Some(Sink::Ws(a, encrypt.clone()));
            let mut keep = match first {
                Some(bytes) => self.handle_tcp(&bytes, &mut sink, addr, key, ws, &mut auth).await,
                None => true,
            };
            while keep {
                let Ok(Some(Ok(msg))) = timeout(30_000, b.next()).await else {
                    break;
                };
                let tungstenite::Message::Binary(bytes) = msg else {
                    continue;
                };
                let mut bytes = BytesMut::from(&bytes[..]);
                if let Some(encrypt) = encrypt.as_ref() {
                    if encrypt.lock().unwrap().dec(&mut bytes).is_err() {
                        log::debug!("Ws connection from {:?}: undecryptable message", addr);
                        break;
                    }
                }
                keep = self.handle_tcp(&bytes, &mut sink, addr, key, ws, &mut auth).await;
            }
        } else {
            let mut codec = BytesCodec::new();
            codec.set_max_packet_length(*MAX_MESSAGE);
            let (mut a, mut b) = Framed::new(stream, codec).split();
            // Rendezvous encryption: key exchange first (see rendezvous_kx).
            let mut encrypt = None;
            let mut first = None;
            let kx = crate::rendezvous_kx::mode();
            let sk = self.inner.sk.as_ref().filter(|_| kx != crate::rendezvous_kx::Mode::Off);
            if let Some(sk) = sk {
                use crate::rendezvous_kx::{handshake, Mode, Outcome};
                match handshake(&mut a, &mut b, sk, 30_000, kx).await {
                    Ok(Outcome::Secured(e, binding)) => {
                        encrypt = Some(e);
                        auth.binding = Some(binding);
                    }
                    Ok(Outcome::Plain(bytes)) if kx == Mode::Optional => first = Some(bytes),
                    Ok(Outcome::Plain(_)) => {
                        log::debug!("Tcp connection from {:?} refused: no key exchange", addr);
                        return Ok(());
                    }
                    Ok(Outcome::Closed) => return Ok(()),
                    Err(err) => {
                        log::debug!("Key exchange with {:?} failed: {}", addr, err);
                        return Ok(());
                    }
                }
            }
            sink = Some(Sink::TcpStream(a, encrypt.clone()));
            let mut keep = match first {
                Some(bytes) => self.handle_tcp(&bytes, &mut sink, addr, key, ws, &mut auth).await,
                None => true,
            };
            while keep {
                let Ok(Some(Ok(mut bytes))) = timeout(30_000, b.next()).await else {
                    break;
                };
                if let Some(encrypt) = encrypt.as_ref() {
                    if encrypt.lock().unwrap().dec(&mut bytes).is_err() {
                        log::debug!("Tcp connection from {:?}: undecryptable message", addr);
                        break;
                    }
                }
                keep = self.handle_tcp(&bytes, &mut sink, addr, key, ws, &mut auth).await;
            }
        }
        if sink.is_none() {
            // HBB-01: on its turn, after any send_to_tcp_keep that has it out put it back.
            self.take_sink(addr).await;
        }
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        if version.is_empty() || self.inner.sk.is_none() {
            Bytes::new()
        } else {
            match self.pm.get(&id).await {
                Some(peer) => {
                    let pk = peer.read().await.pk.clone();
                    sign::sign(
                        &hbb_common::rendezvous_proto::IdPk {
                            id,
                            pk,
                            ..Default::default()
                        }
                        .write_to_bytes()
                        .unwrap_or_default(),
                        self.inner.sk.as_ref().unwrap(),
                    )
                    .into()
                }
                _ => Bytes::new(),
            }
        }
    }

    #[inline]
    fn get_server_sk(key: &str) -> ResultType<(String, Option<sign::SecretKey>)> {
        let mut out_sk = None;
        let mut key = key.to_owned();
        if let Ok(sk) = base64::decode(&key) {
            if sk.len() == sign::SECRETKEYBYTES {
                log::info!("The key is a crypto private key");
                key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                out_sk = Some(sign::SecretKey(tmp));
            }
        }

        if key.is_empty() || key == "-" || key == "_" {
            let (pk, sk) = crate::common::gen_sk(0)?;
            out_sk = sk;
            if !key.is_empty() {
                key = pk;
            }
        }

        if !key.is_empty() {
            log::info!("Key: {}", key);
        }
        Ok((key, out_sk))
    }

    #[inline]
    fn is_lan(&self, addr: SocketAddr) -> bool {
        if let Some(network) = &self.inner.mask {
            match addr {
                SocketAddr::V4(v4_socket_addr) => {
                    return network.contains(*v4_socket_addr.ip());
                }

                SocketAddr::V6(v6_socket_addr) => {
                    if let Some(v4_addr) = v6_socket_addr.ip().to_ipv4() {
                        return network.contains(v4_addr);
                    }
                }
            }
        }
        false
    }
}

async fn check_relay_servers(rs0: Arc<RelayServers>, tx: Sender) {
    let mut futs = Vec::new();
    let rs = Arc::new(Mutex::new(Vec::new()));
    for x in rs0.iter() {
        let mut host = x.to_owned();
        if !host.contains(':') {
            host = format!("{}:{}", host, config::RELAY_PORT);
        }
        let rs = rs.clone();
        let x = x.clone();
        futs.push(tokio::spawn(async move {
            if FramedStream::new(&host, None, CHECK_RELAY_TIMEOUT)
                .await
                .is_ok()
            {
                rs.lock().await.push(x);
            }
        }));
    }
    join_all(futs).await;
    log::debug!("check_relay_servers");
    let rs = std::mem::take(&mut *rs.lock().await);
    if !rs.is_empty() {
        tx.send(Data::RelayServers(rs)).ok();
    }
}

// temp solution to solve udp socket failure
async fn test_hbbs(addr: SocketAddr) -> ResultType<()> {
    let mut addr = addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }

    let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(addr.is_ipv4())).await?;
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_peer(RegisterPeer {
        id: "(:test_hbbs:)".to_owned(),
        ..Default::default()
    });
    let mut last_time_recv = Instant::now();

    let mut timer = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
          _ = timer.tick() => {
              if last_time_recv.elapsed().as_secs() > 12 {
                  bail!("Timeout of test_hbbs");
              }
              socket.send(&msg_out, addr).await?;
          }
          Some(Ok((bytes, _))) = socket.next() => {
              if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                 log::trace!("Recv {:?} of test_hbbs", msg_in);
                 last_time_recv = Instant::now();
              }
          }
        }
    }
}

#[inline]
async fn send_rk_res(
    socket: &mut FramedSocket,
    addr: SocketAddr,
    res: register_pk_response::Result,
) -> ResultType<()> {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_pk_response(RegisterPkResponse {
        result: res.into(),
        ..Default::default()
    });
    socket.send(&msg_out, addr).await
}

async fn create_udp_listener(
    bind_addr: Option<IpAddr>,
    port: i32,
    rmem: usize,
) -> ResultType<FramedSocket> {
    if let Some(bind_addr) = bind_addr {
        let addr = SocketAddr::new(bind_addr, port as _);
        return FramedSocket::new_reuse(&addr, true, rmem).await;
    }
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port as _);
    if let Ok(s) = FramedSocket::new_reuse(&addr, true, rmem).await {
        log::debug!("listen on udp {:?}", s.local_addr());
        return Ok(s);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as _);
    let s = FramedSocket::new_reuse(&addr, true, rmem).await?;
    log::debug!("listen on udp {:?}", s.local_addr());
    Ok(s)
}

#[inline]
async fn create_tcp_listener(bind_addr: Option<IpAddr>, port: i32) -> ResultType<TcpListener> {
    let s = listen_tcp(bind_addr, port as _).await?;
    log::debug!("listen on tcp {:?}", s.local_addr());
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_message_kb_falls_back_to_default_and_is_capped() {
        assert_eq!(max_message_kb(""), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("0"), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("abc"), DEFAULT_MAX_MESSAGE_KB);
        assert_eq!(max_message_kb("256"), 256);
        assert_eq!(max_message_kb(&usize::MAX.to_string()), MAX_MESSAGE_KB_CAP);
    }

    #[test]
    fn default_message_bound_holds_an_online_query_for_5000_ids() {
        let mut msg = RendezvousMessage::new();
        msg.set_online_request(OnlineRequest {
            id: "1234567890".to_owned(),
            peers: (0..5000).map(|i| format!("{i:010}")).collect(),
            ..Default::default()
        });
        let len = msg.write_to_bytes().unwrap().len();
        assert!(len <= DEFAULT_MAX_MESSAGE_KB << 10, "{len}");
    }

    #[test]
    fn relay_uuid_validation() {
        let uuid = "e4c181d0-41c7-4ae6-8ef0-36581b6b2b12";
        assert_eq!(validate_relay_response(uuid, "relay.example"), Ok(()));
        assert_eq!(validate_relay_response("", ""), Ok(()));
        let max_len = "a".repeat(128);
        for value in [
            uuid,
            "E4C181D0-41C7-4AE6-8EF0-36581B6B2B12",
            "e4c181d041c74ae68ef036581b6b2b12",
            "01890a5d-ac96-774b-bcce-b302099a8057",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "a_b-c",
            max_len.as_str(),
        ] {
            assert_eq!(validate_relay_uuid(value), Ok(()), "rejected {value:?}");
        }
        let too_long = "a".repeat(129);
        for value in [
            "",
            "\r\nPING\r\n",
            "e4c181d0-41c7-4ae6-8ef0-36581b6b2b12\n",
            "e4c181d0 41c7",
            "{e4c181d0-41c7-4ae6-8ef0-36581b6b2b12}",
            "e4c181d0\0",
            "é",
            too_long.as_str(),
        ] {
            assert!(validate_relay_uuid(value).is_err(), "accepted {value:?}");
            assert!(validate_relay_response(value, "relay.example").is_err());
        }
    }

    #[hbb_common::tokio::test]
    async fn udp_listener_uses_bind_address() {
        let bind_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = create_udp_listener(Some(bind_addr), 0, 0).await.unwrap();
        assert_eq!(socket.local_addr().unwrap().ip(), bind_addr);
    }

    #[hbb_common::tokio::test]
    async fn punch_reqs_bounded() {
        let max = *PUNCH_REQ_MAX;
        // 31 ids keep every request just outside the 30-entry dedupe window;
        // one request at least, so MAX_PUNCH_REQUESTS=0 is exercised too
        for i in 0..(max * 2).max(1) {
            record_punch_req(
                "1.2.3.4".to_owned(),
                "5.6.7.8".to_owned(),
                format!("peer{}", i % 31),
            )
            .await;
        }
        let lock = PUNCH_REQS.lock().await;
        assert_eq!(lock.len(), max);
        if max > 0 {
            // the oldest half is evicted and the newest kept
            assert_eq!(lock.front().unwrap().to_id, format!("peer{}", max % 31));
            assert_eq!(lock.back().unwrap().to_id, format!("peer{}", (max * 2 - 1) % 31));
        }
    }

    fn pending(uuid: &str) -> RelayPending {
        RelayPending {
            uuid: uuid.to_owned(),
            controller_id: "controller".to_owned(),
            target_id: "asked-for".to_owned(),
            at: Instant::now(),
            seq: 0,
        }
    }

    fn subject(uuid: &str, reply: bool) -> TicketSubject {
        TicketSubject {
            uuid: uuid.into(),
            controller_id: "controller".into(),
            controlled_id: "asked-for".into(),
            reply,
        }
    }

    fn from(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    #[test]
    fn controller_started_relay_takes_the_requests_uuid_and_sends_nothing_back() {
        // The controlled side answers a forwarded RequestRelay without a uuid or id.
        let rr = RelayResponse::default();
        let found = relay_ticket_subject(&rr, &pending("u-1"), "asked-for");
        assert_eq!(found, Some(subject("u-1", false)));
    }

    #[test]
    fn controlled_started_relay_takes_its_own_uuid_and_gets_a_ticket_back() {
        let mut rr = RelayResponse {
            uuid: "u-2".into(),
            ..Default::default()
        };
        rr.set_id("asked-for".into());
        // After a punch request the pending entry has ids but no uuid.
        let found = relay_ticket_subject(&rr, &pending(""), "asked-for");
        assert_eq!(found, Some(subject("u-2", true)));
        // A uuid the controller's RequestRelay named too must be the same.
        assert_eq!(relay_ticket_subject(&rr, &pending("u-2"), "asked-for"), Some(subject("u-2", true)));
        assert_eq!(relay_ticket_subject(&rr, &pending("u-1"), "asked-for"), None);
    }

    #[test]
    fn no_uuid_anywhere_no_tickets() {
        let rr = RelayResponse::default();
        assert_eq!(relay_ticket_subject(&rr, &pending(""), "asked-for"), None);
    }

    #[test]
    fn only_the_proven_device_asked_for_gets_tickets() {
        // From connection B an attacker answers with uuid X for its other connection A.
        let a = from("198.51.100.7", 50_000);
        let rr = RelayResponse {
            uuid: "X".into(),
            ..Default::default()
        };
        let now = Instant::now();
        let mut pendings = RelayPendings::new(16, 4);
        // A made no request hbbs passed on: nothing, whoever B is.
        assert_eq!(answer_subject(&mut pendings, &rr, a, Some("asked-for"), now), None);
        pendings.insert(a, pending(""), now);
        // A connection that proved no device, or another device than A asked for, gets nothing,
        // and leaves A's request for the real answer.
        assert_eq!(answer_subject(&mut pendings, &rr, a, None, now), None);
        assert_eq!(answer_subject(&mut pendings, &rr, a, Some("someone-else"), now), None);
        assert_eq!(answer_subject(&mut pendings, &rr, a, Some(""), now), None);
        assert_eq!(pendings.map.len(), 1);
        let found = answer_subject(&mut pendings, &rr, a, Some("asked-for"), now);
        assert_eq!(found, Some(subject("X", true)));
        // Used up: a second answer gets nothing.
        assert_eq!(answer_subject(&mut pendings, &rr, a, Some("asked-for"), now), None);
        assert!(pendings.map.is_empty() && pendings.order.is_empty() && pendings.by_source.is_empty());
        // Nor does one after the request expired.
        pendings.insert(a, pending(""), now);
        let later = now + Duration::from_secs(crate::relay_ticket::TTL_SECS);
        assert_eq!(answer_subject(&mut pendings, &rr, a, Some("asked-for"), later), None);
    }

    #[test]
    fn a_flood_from_one_source_only_displaces_its_own_requests() {
        let now = Instant::now();
        let mut pendings = RelayPendings::new(RELAY_PENDING_MAX, RELAY_PENDING_PER_SOURCE);
        let victim = from("203.0.113.9", 1_000);
        pendings.insert(victim, pending(""), now);
        for port in 0..10_000u16 {
            pendings.insert(from("198.51.100.7", 20_000 + port), pending(""), now);
        }
        assert_eq!(pendings.map.len(), 1 + RELAY_PENDING_PER_SOURCE);
        assert!(pendings.map.contains_key(&victim));
        // The flooder's newest requests are the ones it keeps.
        assert!(pendings.map.contains_key(&from("198.51.100.7", 29_999)));
        assert!(!pendings.map.contains_key(&from("198.51.100.7", 20_000)));
        // An IPv6 /64 is one source.
        for i in 0..100u16 {
            let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, i);
            pendings.insert(SocketAddr::new(IpAddr::V6(ip), 443), pending(""), now);
        }
        assert_eq!(pendings.map.len(), 1 + 2 * RELAY_PENDING_PER_SOURCE);
        assert_eq!(pendings.order.len(), pendings.map.len());
        let indexed: usize = pendings.by_source.values().map(BTreeSet::len).sum();
        assert_eq!(indexed, pendings.map.len());
    }

    #[test]
    fn when_full_the_oldest_request_makes_room() {
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let mut pendings = RelayPendings::new(4, 64);
        for i in 0..6u8 {
            pendings.insert(from(&format!("192.0.2.{}", i), 1), pending(""), at(i as u64));
        }
        assert_eq!(pendings.map.len(), 4);
        assert!(!pendings.map.contains_key(&from("192.0.2.0", 1)));
        assert!(!pendings.map.contains_key(&from("192.0.2.1", 1)));
        assert!(pendings.map.contains_key(&from("192.0.2.5", 1)));
        // A request again from the same connection replaces its own, taking no more room.
        pendings.insert(from("192.0.2.2", 1), pending("again"), at(10));
        assert_eq!(pendings.map.len(), 4);
        assert!(pendings.map.contains_key(&from("192.0.2.3", 1)));
        assert_eq!(pendings.map[&from("192.0.2.2", 1)].uuid, "again");
        // Expired requests go before anything else.
        pendings.insert(from("192.0.2.9", 1), pending(""), at(crate::relay_ticket::TTL_SECS + 10));
        assert_eq!(pendings.map.len(), 1);
        assert_eq!((pendings.order.len(), pendings.by_source.len()), (1, 1));
    }
}
