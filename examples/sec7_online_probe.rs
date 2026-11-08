// Probe: online states asked on hbbs's main listener (TCP or WebSocket) after the signed
// key exchange, as managed clients do from build 33. Usage:
//   sec7_online_probe <host:port or ws(s) URL> <hbbs public key base64> <asking id> <id>...
// The asking id must be on hbbs's approved list, or no answer comes back.
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        bail!("usage: sec7_online_probe <host:port or ws(s) URL> <hbbs public key base64> <asking id> <id>...");
    }
    let pk = hbb_common::base64::decode(&args[2])?;
    let rs_pk = sign::PublicKey::from_slice(&pk).ok_or_else(|| anyhow!("bad public key"))?;
    let asking = args[3].clone();
    let ids: Vec<String> = args[4..].to_vec();
    let mut c = connect(&args[1]).await?;
    let server = read_server_kx(&mut c, &rs_pk).await?;
    reply_kx(&mut c, &server, 1).await?;
    let mut msg = RendezvousMessage::new();
    msg.set_online_request(OnlineRequest { id: asking, peers: ids.clone(), ..Default::default() });
    c.send(&msg).await?;
    let bytes = c.next_timeout(5000).await.ok_or_else(|| anyhow!("no answer (refused)"))??;
    let Some(rendezvous_message::Union::OnlineResponse(r)) = RendezvousMessage::parse_from_bytes(&bytes)?.union else {
        bail!("answer is not an OnlineResponse");
    };
    for (i, id) in ids.iter().enumerate() {
        let on = r.states.get(i / 8).map_or(false, |b| b & (0x01 << (7 - i % 8)) != 0);
        println!("{id} {}", if on { "online" } else { "offline" });
    }
    println!("OK online response over the key-exchanged connection ({} state bytes)", r.states.len());
    Ok(())
}
