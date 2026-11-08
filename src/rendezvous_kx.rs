//! Rendezvous encryption: the signed key exchange hbbs opens each TCP rendezvous connection with (and
//! each WebSocket one, so a client that fell back to it doesn't rely on TLS alone), so that
//! everything after it is encrypted. It is the server half of the client's `secure_tcp`
//! (rustdesk src/common.rs `key_exchange`, whose test stub is the reference for version 1).
//!
//! hbbs sends KeyExchange{keys: [sign(ephemeral X25519 public key)], version, signed_params}
//! first. Bit 255 of the signed key is set: X25519 ignores it, and clients that know signed
//! parameters then require them, so the advertised version can't be lowered on the way. A client
//! that does the exchange answers KeyExchange{[its ephemeral public key, the sealed key], picked
//! version}. Clients that don't skip our first message (get_next_nonkeyexchange_msg) and talk
//! in the clear, which is allowed unless the mode is `required`.
//!
//! The mode is off (no key exchange), optional or required; `required` also refuses the original
//! version-0 scheme, which uses one key in both directions. It comes from rendezvous_settings in the
//! working directory (`rendezvous-encryption=<mode>`, written from the RDS Config page by the
//! host's sync timer), re-read every 15 s, else from RENDEZVOUS_ENCRYPTION, else off.
//! Every 5 minutes the connection counts go to the log and to STATS_FILE for RDS.
use hbb_common::{
    bail,
    bytes::{Bytes, BytesMut},
    futures_util::{Sink, SinkExt, Stream, StreamExt},
    log,
    protobuf::Message as _,
    rendezvous_proto::{rendezvous_message, KeyExchange, KxParams, RendezvousMessage},
    sodiumoxide::crypto::{box_, sign},
    tcp::{Encrypt, KxTranscript, KX_PARAMS_DOMAIN, KX_VERSION_LATEST},
    timeout, ResultType,
};
use once_cell::sync::Lazy;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime},
};

const STATS_FILE: &str = "rendezvous_stats";
const REPORT_EVERY: Duration = Duration::from_secs(300);

// How connections arrived since the last report: readiness numbers for moving to `required`.
static SECURED_V1: AtomicU64 = AtomicU64::new(0);
static SECURED_V0: AtomicU64 = AtomicU64::new(0);
static PLAINTEXT: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);

/// Every 5 minutes, logs the counts and writes them to STATS_FILE (JSON, replaced atomically).
pub(crate) fn spawn_report() {
    mode();
    hbb_common::tokio::spawn(async {
        let mut every = hbb_common::tokio::time::interval(REPORT_EVERY);
        every.tick().await;
        loop {
            every.tick().await;
            let (v1, v0, plaintext, failed) = (
                SECURED_V1.swap(0, Ordering::Relaxed),
                SECURED_V0.swap(0, Ordering::Relaxed),
                PLAINTEXT.swap(0, Ordering::Relaxed),
                FAILED.swap(0, Ordering::Relaxed),
            );
            let mode = mode();
            if mode != Mode::Off {
                log::info!(
                    "rendezvous-encryption, last 5 min: v1={} v0={} plaintext={} failed={}",
                    v1, v0, plaintext, failed
                );
            }
            let at = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let json = format!(
                "{{\"at\":{at},\"window_seconds\":{},\"mode\":\"{}\",\"v1\":{v1},\"v0\":{v0},\"plaintext\":{plaintext},\"failed\":{failed}}}\n",
                REPORT_EVERY.as_secs(),
                mode.as_str()
            );
            let tmp = format!("{STATS_FILE}.tmp");
            if let Err(err) = std::fs::write(&tmp, json).and_then(|_| std::fs::rename(&tmp, STATS_FILE)) {
                log::warn!("rendezvous-encryption: could not write {}: {}", STATS_FILE, err);
            }
        }
    });
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    Off,
    Optional,
    Required,
}

impl Mode {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "off" => Some(Mode::Off),
            "optional" => Some(Mode::Optional),
            "required" => Some(Mode::Required),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Optional => "optional",
            Mode::Required => "required",
        }
    }
}

/// The mode now (see rendezvous_settings); changes are logged.
pub(crate) fn mode() -> Mode {
    static LAST: Lazy<Mutex<Option<Mode>>> = Lazy::new(|| Mutex::new(None));
    let (value, source) = crate::rendezvous_settings::get("rendezvous-encryption");
    let mode = value.as_deref().and_then(Mode::parse).unwrap_or(Mode::Off);
    let mut last = LAST.lock().unwrap();
    if *last != Some(mode) {
        log::info!("rendezvous-encryption mode: {:?} (from {})", mode, source);
        *last = Some(mode);
    }
    mode
}

/// A connection's encryption, shared by its reader and by the sink kept for later replies.
pub(crate) type Shared = Arc<Mutex<Encrypt>>;

/// KxParams.managed_capabilities bit: this connection takes a DeviceAuth (device_auth.rs).
pub(crate) const CAP_DEVICE_AUTH: u32 = 1;

/// What the exchange was, so a device can sign this connection and no other (device_auth.rs).
pub(crate) struct Binding {
    pub initiator_pk: Vec<u8>,
    pub responder_pk: Vec<u8>,
    pub version: u32,
}

pub(crate) enum Outcome {
    Secured(Shared, Binding),
    /// The client didn't do the exchange; this is its first message, already read.
    Plain(BytesMut),
    /// Nothing arrived in time, or the connection ended.
    Closed,
}

pub(crate) async fn handshake<W, R>(
    sink: &mut W,
    stream: &mut R,
    sk: &sign::SecretKey,
    read_timeout_ms: u64,
    mode: Mode,
) -> ResultType<Outcome>
where
    W: Sink<Bytes> + Unpin,
    W::Error: std::error::Error + Send + Sync + 'static,
    R: Stream<Item = Result<BytesMut, std::io::Error>> + Unpin,
{
    let res = exchange(sink, stream, sk, read_timeout_ms, mode).await;
    let counter = match &res {
        Ok((Outcome::Secured(..), 0)) => &SECURED_V0,
        Ok((Outcome::Secured(..), _)) => &SECURED_V1,
        Ok((Outcome::Plain(_), _)) => &PLAINTEXT,
        Ok((Outcome::Closed, _)) => return res.map(|(outcome, _)| outcome),
        Err(_) => &FAILED,
    };
    counter.fetch_add(1, Ordering::Relaxed);
    res.map(|(outcome, _)| outcome)
}

/// The outcome, and the version the client picked (0 when it did no exchange).
async fn exchange<W, R>(
    sink: &mut W,
    stream: &mut R,
    sk: &sign::SecretKey,
    read_timeout_ms: u64,
    mode: Mode,
) -> ResultType<(Outcome, u32)>
where
    W: Sink<Bytes> + Unpin,
    W::Error: std::error::Error + Send + Sync + 'static,
    R: Stream<Item = Result<BytesMut, std::io::Error>> + Unpin,
{
    let (eph_pk, eph_sk) = box_::gen_keypair();
    let mut advertised = eph_pk.0;
    advertised[31] |= 0x80;
    let params = KxParams {
        pk: advertised.to_vec().into(),
        version: KX_VERSION_LATEST,
        managed_capabilities: if crate::device_auth::offered() { CAP_DEVICE_AUTH } else { 0 },
        ..Default::default()
    };
    let mut signed_params = KX_PARAMS_DOMAIN.to_vec();
    signed_params.extend(params.write_to_bytes()?);
    let mut msg = RendezvousMessage::new();
    msg.set_key_exchange(KeyExchange {
        keys: vec![sign::sign(&advertised, sk).into()],
        version: KX_VERSION_LATEST,
        signed_params: sign::sign(&signed_params, sk).into(),
        ..Default::default()
    });
    sink.send(Bytes::from(msg.write_to_bytes()?)).await?;

    let first = match timeout(read_timeout_ms, stream.next()).await {
        Ok(Some(Ok(bytes))) => bytes,
        _ => return Ok((Outcome::Closed, 0)),
    };
    let ex = match RendezvousMessage::parse_from_bytes(&first).map(|m| m.union) {
        Ok(Some(rendezvous_message::Union::KeyExchange(ex))) => ex,
        _ => return Ok((Outcome::Plain(first), 0)),
    };
    if ex.keys.len() != 2 {
        bail!("key exchange reply carries {} keys", ex.keys.len());
    }
    if ex.version > KX_VERSION_LATEST {
        bail!("key exchange reply picked version {}", ex.version);
    }
    if ex.version == 0 && mode == Mode::Required {
        bail!("key exchange version 0 refused in required mode");
    }
    let key = Encrypt::decode(&ex.keys[1], &ex.keys[0], &eph_sk)?;
    let encrypt = if ex.version == 0 {
        Encrypt::new(key)
    } else {
        Encrypt::new_split(
            key,
            false,
            &KxTranscript {
                initiator_pk: &ex.keys[0],
                responder_pk: &advertised,
                advertised: KX_VERSION_LATEST,
                picked: ex.version,
            },
        )?
    };
    let binding = Binding {
        initiator_pk: ex.keys[0].to_vec(),
        responder_pk: advertised.to_vec(),
        version: ex.version,
    };
    Ok((Outcome::Secured(Arc::new(Mutex::new(encrypt)), binding), ex.version))
}
