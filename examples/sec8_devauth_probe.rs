// Probe: DeviceAuth (passport + signature over this connection's key exchange) on hbbs's
// main listener, as managed clients do from build 34. Test keys only (fixed seeds).
//   sec8_devauth_probe setup <dir>            writes root.pub, approved_ids, approved_keys
//   sec8_devauth_probe <addr> <hbbs pk b64> <case>
// Cases: caps | online:<auth>:<asking id> | punch:<auth>:<target id>
// <auth>: none, valid-A, valid-B, expired-A, grace-A, wrongroot-A, wrongkey-A, nokey-C,
//         notapproved-D, malformed, noscope-A, replay-A
// Prints one line: "RESULT <case> <answered|refused|caps=N> <detail>".
use ed25519_dalek::{Signer, SigningKey};
use hbb_common::{
    anyhow::{anyhow, bail, Result},
    protobuf::Message as _,
    rendezvous_proto::*,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::{KxTranscript, KX_PARAMS_DOMAIN},
    tokio::{self, net::TcpStream},
    websocket::WsFramedStream,
    Stream,
};
use rdc_passport::{b64, fingerprint, kid_for, sign_ikc, sign_passport, PassportBody, VERSION};
use std::time::{SystemTime, UNIX_EPOCH};

const ID_A: &str = "123456789";
const ID_B: &str = "222222222";
const ID_C: &str = "333333333"; // approved, no identity key on file
const ID_D: &str = "999999999"; // not approved
const DOMAIN: &[u8] = b"rdcp1-devauth\0";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn root() -> SigningKey {
    key(1)
}
fn identity(id: &str) -> SigningKey {
    match id {
        ID_A => key(10),
        ID_B => key(11),
        ID_C => key(12),
        _ => key(13),
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn passport(id: &str, identity_key: &SigningKey, root_key: &SigningKey, exp: i64, scopes: &[&str]) -> String {
    let issuing = key(3);
    let ikc = sign_ikc(root_key, &issuing.verifying_key(), now() - 3600, now() + 30 * 86400);
    let body = PassportBody {
        typ: "rdc-passport".into(),
        v: VERSION,
        serial: "00112233445566778899aabbccddeeff".into(),
        rid: id.into(),
        did: "6f1c2a3b-0000-4000-8000-000000000001".into(),
        idk: b64(identity_key.verifying_key().as_bytes()),
        idk_alg: "ed25519".into(),
        rdk: b64(key(20).verifying_key().as_bytes()),
        prot: "dpapi".into(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        iat: now() - 60,
        nbf: now() - 60,
        exp,
        ikid: kid_for(&issuing.verifying_key()),
    };
    sign_passport(&issuing, &ikc, &body)
}

/// (passport, signing identity key, sign a different connection instead of this one)
fn auth_variant(name: &str) -> Result<Option<(String, SigningKey, bool)>> {
    let all = ["hbbs", "hbbr", "rds", "chat", "rustdrop", "peer"];
    let day = now() + 86400;
    Ok(Some(match name {
        "none" => return Ok(None),
        "valid-A" => (passport(ID_A, &identity(ID_A), &root(), day, &all), identity(ID_A), false),
        "valid-B" => (passport(ID_B, &identity(ID_B), &root(), day, &all), identity(ID_B), false),
        "expired-A" => (passport(ID_A, &identity(ID_A), &root(), now() - 40 * 86400, &all), identity(ID_A), false),
        "grace-A" => (passport(ID_A, &identity(ID_A), &root(), now() - 2 * 86400, &all), identity(ID_A), false),
        "wrongroot-A" => (passport(ID_A, &identity(ID_A), &key(2), day, &all), identity(ID_A), false),
        "wrongkey-A" => (passport(ID_A, &key(14), &root(), day, &all), key(14), false),
        "nokey-C" => (passport(ID_C, &identity(ID_C), &root(), day, &all), identity(ID_C), false),
        "notapproved-D" => (passport(ID_D, &identity(ID_D), &root(), day, &all), identity(ID_D), false),
        "malformed" => ("rdcp1.not.a.real.passport".into(), identity(ID_A), false),
        "noscope-A" => (passport(ID_A, &identity(ID_A), &root(), day, &["rds"]), identity(ID_A), false),
        "replay-A" => (passport(ID_A, &identity(ID_A), &root(), day, &all), identity(ID_A), true),
        other => bail!("unknown auth variant {other}"),
    }))
}

fn setup(dir: &str) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(format!("{dir}/root.pub"), b64(root().verifying_key().as_bytes()))?;
    std::fs::write(format!("{dir}/approved_ids"), format!("{ID_A}\n{ID_B}\n{ID_C}\n"))?;
    let fp = |id: &str| fingerprint(identity(id).verifying_key().as_bytes());
    std::fs::write(format!("{dir}/approved_keys"), format!("{ID_A} {}\n{ID_B} {}\n", fp(ID_A), fp(ID_B)))?;
    println!("setup done in {dir}");
    Ok(())
}

struct Server {
    eph_pk: Vec<u8>,
    advertised: u32,
    caps: u32,
}

async fn connect(addr: &str) -> Result<Stream> {
    if addr.starts_with("ws://") || addr.starts_with("wss://") {
        return Ok(Stream::WebSocket(WsFramedStream::new(addr, None, None, 5000).await?));
    }
    let stream = TcpStream::connect(addr).await?;
    let local = stream.peer_addr()?;
    Ok(Stream::from(stream, local))
}

async fn read_server_kx(conn: &mut Stream, rs_pk: &sign::PublicKey) -> Result<Server> {
    let bytes = conn.next_timeout(5000).await.ok_or_else(|| anyhow!("no first message"))??;
    let Some(rendezvous_message::Union::KeyExchange(ex)) = RendezvousMessage::parse_from_bytes(&bytes)?.union else {
        bail!("first message is not a key exchange");
    };
    let eph_pk = sign::verify(&ex.keys[0], rs_pk).map_err(|_| anyhow!("bad signature on the ephemeral key"))?;
    let signed = sign::verify(&ex.signed_params, rs_pk).map_err(|_| anyhow!("bad signature on the parameters"))?;
    let params = KxParams::parse_from_bytes(
        signed.strip_prefix(KX_PARAMS_DOMAIN).ok_or_else(|| anyhow!("no domain prefix"))?,
    )?;
    if params.pk[..] != eph_pk[..] || params.version != ex.version {
        bail!("signed parameters don't match the message");
    }
    Ok(Server { eph_pk, advertised: ex.version, caps: params.managed_capabilities })
}

/// Completes the exchange; returns our ephemeral public key (the transcript's initiator key).
async fn reply_kx(conn: &mut Stream, server: &Server, picked: u32) -> Result<Vec<u8>> {
    let mut their = [0u8; box_::PUBLICKEYBYTES];
    their.copy_from_slice(&server.eph_pk);
    let (our_pk, our_sk) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let sealed = box_::seal(&key.0, &box_::Nonce([0u8; box_::NONCEBYTES]), &box_::PublicKey(their), &our_sk);
    let mut msg = RendezvousMessage::new();
    msg.set_key_exchange(KeyExchange {
        keys: vec![our_pk.0.to_vec().into(), sealed.into()],
        version: picked,
        ..Default::default()
    });
    conn.send(&msg).await?;
    conn.set_negotiated_key(
        key,
        true,
        &KxTranscript { initiator_pk: &our_pk.0, responder_pk: &server.eph_pk, advertised: server.advertised, picked },
    )?;
    Ok(our_pk.0.to_vec())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "setup" {
        return setup(&args[2]);
    }
    if args.len() != 4 {
        bail!("usage: sec8_devauth_probe setup <dir> | <addr> <hbbs pk b64> <case>");
    }
    let (addr, case) = (&args[1], &args[3]);
    let hbbs_pk = hbb_common::base64::decode(&args[2])?;
    let rs_pk = sign::PublicKey::from_slice(&hbbs_pk).ok_or_else(|| anyhow!("bad public key"))?;
    let mut c = connect(addr).await?;
    let server = read_server_kx(&mut c, &rs_pk).await?;
    let picked = 1;
    let our_pk = reply_kx(&mut c, &server, picked).await?;
    if case == "caps" {
        println!("RESULT caps caps={}", server.caps);
        return Ok(());
    }
    let parts: Vec<&str> = case.splitn(3, ':').collect();
    if parts.len() != 3 {
        bail!("case must be kind:auth:id");
    }
    let (kind, auth, id) = (parts[0], parts[1], parts[2]);
    if let Some((token, identity_key, replay)) = auth_variant(auth)? {
        let initiator = if replay { box_::gen_keypair().0 .0.to_vec() } else { our_pk.clone() };
        let mut signed = DOMAIN.to_vec();
        signed.extend_from_slice(&hbbs_pk);
        signed.extend_from_slice(&initiator);
        signed.extend_from_slice(&server.eph_pk);
        signed.extend_from_slice(&picked.to_le_bytes());
        let mut msg = RendezvousMessage::new();
        msg.set_device_auth(DeviceAuth {
            passport: token,
            signature: identity_key.sign(&signed).to_bytes().to_vec().into(),
            ..Default::default()
        });
        c.send(&msg).await?;
    }
    let mut msg = RendezvousMessage::new();
    // Two online requests on one connection; hbbs keeps it open after the first answer.
    if kind == "online2" {
        let mut answers = 0;
        for _ in 0..2 {
            let mut m = RendezvousMessage::new();
            m.set_online_request(OnlineRequest { id: id.into(), peers: vec![ID_B.into()], ..Default::default() });
            if c.send(&m).await.is_err() {
                break;
            }
            match c.next_timeout(3000).await {
                Some(Ok(bytes)) if matches!(
                    RendezvousMessage::parse_from_bytes(&bytes).ok().and_then(|m| m.union),
                    Some(rendezvous_message::Union::OnlineResponse(_))
                ) => answers += 1,
                _ => break,
            }
        }
        println!("RESULT {case} answered {answers} of 2 on one connection");
        return Ok(());
    }
    match kind {
        "online" => msg.set_online_request(OnlineRequest { id: id.into(), peers: vec![ID_B.into()], ..Default::default() }),
        "punch" => msg.set_punch_hole_request(PunchHoleRequest { id: id.into(), ..Default::default() }),
        // A controlled device's RelayResponse; "noid" sends it without an id, like a WebRTC answer.
        // hbbs forwards it and closes either way, so the outcome shows only in its log and counts.
        "reply" => {
            let mut rr = RelayResponse {
                socket_addr: hbb_common::AddrMangle::encode("127.0.0.1:9".parse()?).into(),
                ..Default::default()
            };
            if id != "noid" {
                rr.set_id(id.into());
            }
            msg.set_relay_response(rr);
        }
        other => bail!("unknown kind {other}"),
    }
    c.send(&msg).await?;
    let answer = match c.next_timeout(3000).await {
        Some(Ok(bytes)) => RendezvousMessage::parse_from_bytes(&bytes).ok().and_then(|m| m.union),
        _ => None,
    };
    match answer {
        Some(rendezvous_message::Union::OnlineResponse(_)) => println!("RESULT {case} answered online response"),
        Some(rendezvous_message::Union::PunchHoleResponse(r)) => {
            println!("RESULT {case} answered punch response {:?}", r.failure.enum_value())
        }
        Some(other) => println!("RESULT {case} answered {:?}", other),
        None => println!("RESULT {case} refused no answer"),
    }
    Ok(())
}
