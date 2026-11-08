// Probe: the hbbs rendezvous key exchange over TCP or WebSocket, from the client side.
// Usage: sec6_kx_probe <host:port of hbbs TCP, or ws(s):// URL of its WebSocket> <hbbs public key, base64> <optional|required>
// Plays a current client (version 1), a legacy client (version 0), a client that doesn't do the
// exchange, and a malformed reply, and checks each outcome against what the mode should allow.
use hbb_common::{
    anyhow::{anyhow, bail, Result},
    protobuf::Message as _,
    rendezvous_proto::*,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::{KxTranscript, KX_PARAMS_DOMAIN},
    websocket::WsFramedStream,
    Stream,
    tokio::{self, net::TcpStream},
};

struct Server {
    eph_pk: Vec<u8>,
    advertised: u32,
}

async fn connect(addr: &str) -> Result<Stream> {
    if addr.starts_with("ws://") || addr.starts_with("wss://") {
        return Ok(Stream::WebSocket(WsFramedStream::new(addr, None, None, 5000).await?));
    }
    let stream = TcpStream::connect(addr).await?;
    let local = stream.peer_addr()?;
    Ok(Stream::from(stream, local))
}

/// The client's checks on the server's first message (rustdesk common.rs key_exchange).
async fn read_server_kx(conn: &mut Stream, rs_pk: &sign::PublicKey) -> Result<Server> {
    let bytes = conn.next_timeout(5000).await.ok_or_else(|| anyhow!("no first message"))??;
    let msg = RendezvousMessage::parse_from_bytes(&bytes)?;
    let Some(rendezvous_message::Union::KeyExchange(ex)) = msg.union else {
        bail!("first message is not a key exchange");
    };
    if ex.keys.len() != 1 {
        bail!("server key exchange carries {} keys", ex.keys.len());
    }
    let eph_pk = sign::verify(&ex.keys[0], rs_pk).map_err(|_| anyhow!("bad signature on the ephemeral key"))?;
    if eph_pk.len() != box_::PUBLICKEYBYTES {
        bail!("ephemeral key length {}", eph_pk.len());
    }
    if eph_pk[31] & 0x80 == 0 {
        bail!("high bit not set: signed parameters not required");
    }
    let signed = sign::verify(&ex.signed_params, rs_pk).map_err(|_| anyhow!("bad signature on the parameters"))?;
    let params = signed
        .strip_prefix(KX_PARAMS_DOMAIN)
        .ok_or_else(|| anyhow!("parameters lack the domain prefix"))?;
    let params = KxParams::parse_from_bytes(params)?;
    if params.pk[..] != eph_pk[..] || params.version != ex.version {
        bail!("signed parameters don't match the message");
    }
    Ok(Server { eph_pk, advertised: ex.version })
}

/// Seals a fresh session key to the server's ephemeral key and keys the stream like the client.
async fn reply_kx(conn: &mut Stream, server: &Server, picked: u32) -> Result<()> {
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
        &KxTranscript {
            initiator_pk: &our_pk.0,
            responder_pk: &server.eph_pk,
            advertised: server.advertised,
            picked,
        },
    )?;
    Ok(())
}

/// A request hbbs answers on the same connection; Ok(true) when the answer came back readable.
async fn round_trip(conn: &mut Stream) -> Result<bool> {
    let mut msg = RendezvousMessage::new();
    msg.set_test_nat_request(TestNatRequest { serial: 7, ..Default::default() });
    conn.send(&msg).await?;
    match conn.next_timeout(5000).await {
        Some(Ok(bytes)) => Ok(matches!(
            RendezvousMessage::parse_from_bytes(&bytes).map(|m| m.union),
            Ok(Some(rendezvous_message::Union::TestNatResponse(_)))
        )),
        _ => Ok(false),
    }
}

async fn case(name: &str, expect_answer: bool, run: impl std::future::Future<Output = Result<bool>>) -> bool {
    let got = match run.await {
        Ok(answered) => answered,
        Err(err) => {
            println!("  ({name}: {err})");
            false
        }
    };
    let pass = got == expect_answer;
    println!(
        "{} {name}: {} (expected {})",
        if pass { "PASS" } else { "FAIL" },
        if got { "answered" } else { "refused" },
        if expect_answer { "answered" } else { "refused" }
    );
    pass
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        bail!("usage: sec6_kx_probe <host:port or ws(s) URL> <hbbs public key base64> <optional|required>");
    }
    let (addr, required) = (args[1].as_str(), args[3] == "required");
    let pk = hbb_common::base64::decode(&args[2])?;
    let rs_pk = sign::PublicKey::from_slice(&pk).ok_or_else(|| anyhow!("bad public key"))?;
    let mut all = true;

    all &= case("version-1 client", true, async {
        let mut c = connect(addr).await?;
        let server = read_server_kx(&mut c, &rs_pk).await?;
        if server.advertised != 1 {
            bail!("server advertises version {}", server.advertised);
        }
        reply_kx(&mut c, &server, 1).await?;
        round_trip(&mut c).await
    })
    .await;
    all &= case("version-0 (legacy) client", !required, async {
        let mut c = connect(addr).await?;
        let server = read_server_kx(&mut c, &rs_pk).await?;
        reply_kx(&mut c, &server, 0).await?;
        round_trip(&mut c).await
    })
    .await;
    all &= case("client without the exchange (plaintext)", !required, async {
        let mut c = connect(addr).await?;
        read_server_kx(&mut c, &rs_pk).await?;
        round_trip(&mut c).await
    })
    .await;
    all &= case("malformed exchange reply", false, async {
        let mut c = connect(addr).await?;
        read_server_kx(&mut c, &rs_pk).await?;
        let mut msg = RendezvousMessage::new();
        msg.set_key_exchange(KeyExchange { keys: vec![vec![1u8; 32].into()], version: 1, ..Default::default() });
        c.send(&msg).await?;
        round_trip(&mut c).await
    })
    .await;
    all &= case("wrong key: client keyed but server can't read", false, async {
        // Keys its side for version 1 but tells the server version 0: the halves differ.
        let mut c = connect(addr).await?;
        let server = read_server_kx(&mut c, &rs_pk).await?;
        let mut their = [0u8; box_::PUBLICKEYBYTES];
        their.copy_from_slice(&server.eph_pk);
        let (our_pk, our_sk) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let sealed = box_::seal(&key.0, &box_::Nonce([0u8; box_::NONCEBYTES]), &box_::PublicKey(their), &our_sk);
        let mut msg = RendezvousMessage::new();
        msg.set_key_exchange(KeyExchange { keys: vec![our_pk.0.to_vec().into(), sealed.into()], version: 0, ..Default::default() });
        c.send(&msg).await?;
        c.set_negotiated_key(key, true, &KxTranscript { initiator_pk: &our_pk.0, responder_pk: &server.eph_pk, advertised: 1, picked: 1 })?;
        round_trip(&mut c).await
    })
    .await;
    println!("{}", if all { "ALL PASS" } else { "SOME FAILED" });
    Ok(())
}
