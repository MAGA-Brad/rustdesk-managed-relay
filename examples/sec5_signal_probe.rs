// Probe: WebRTC signaling through hbbs, playing both a controller and a target.
// Usage: sec5_signal_probe <host-nonloopback> <hbbs_port> <hbbs public key base64> <on|off>
// The target registers over UDP from <host>; the controller connects over TCP from 127.0.0.1, so
// hbbs sees two addresses (one address would make it fetch local addresses instead of punching).
// Both TCP connections do the version-1 key exchange like current clients.
use hbb_common::{
    anyhow::{anyhow, bail, Result},
    protobuf::Message as _,
    rendezvous_proto::*,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::{FramedStream, KxTranscript, KX_PARAMS_DOMAIN},
    tokio,
    udp::FramedSocket,
};
use std::net::SocketAddr;

const TARGET: &str = "sec5sigprobe";

async fn secured(addr: &str, rs_pk: &sign::PublicKey) -> Result<FramedStream> {
    let mut c = FramedStream::new(addr, None, 3000).await?;
    let bytes = c.next_timeout(5000).await.ok_or_else(|| anyhow!("no key exchange"))??;
    let Some(rendezvous_message::Union::KeyExchange(ex)) = RendezvousMessage::parse_from_bytes(&bytes)?.union else {
        bail!("first message is not a key exchange");
    };
    let eph = sign::verify(&ex.keys[0], rs_pk).map_err(|_| anyhow!("bad signature"))?;
    let params = sign::verify(&ex.signed_params, rs_pk).map_err(|_| anyhow!("bad params signature"))?;
    let params = KxParams::parse_from_bytes(params.strip_prefix(KX_PARAMS_DOMAIN).ok_or_else(|| anyhow!("no domain"))?)?;
    if params.pk[..] != eph[..] {
        bail!("params don't match");
    }
    let mut their = [0u8; box_::PUBLICKEYBYTES];
    their.copy_from_slice(&eph);
    let (our_pk, our_sk) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let sealed = box_::seal(&key.0, &box_::Nonce([0u8; box_::NONCEBYTES]), &box_::PublicKey(their), &our_sk);
    let mut msg = RendezvousMessage::new();
    msg.set_key_exchange(KeyExchange { keys: vec![our_pk.0.to_vec().into(), sealed.into()], version: 1, ..Default::default() });
    c.send(&msg).await?;
    c.set_key_split(key, true, &KxTranscript { initiator_pk: &our_pk.0, responder_pk: &eph, advertised: ex.version, picked: 1 })?;
    Ok(c)
}

async fn next_tcp(c: &mut FramedStream, ms: u64) -> Option<rendezvous_message::Union> {
    match c.next_timeout(ms).await {
        Some(Ok(b)) => RendezvousMessage::parse_from_bytes(&b).ok().and_then(|m| m.union),
        _ => None,
    }
}

async fn next_udp(u: &mut FramedSocket, ms: u64) -> Option<rendezvous_message::Union> {
    match u.next_timeout(ms).await {
        Some(Ok((b, _))) => RendezvousMessage::parse_from_bytes(&b).ok().and_then(|m| m.union),
        _ => None,
    }
}

fn check(all: &mut bool, name: &str, ok: bool, detail: String) {
    *all &= ok;
    println!("{} {name}{}", if ok { "PASS" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!(" ({detail})") });
}

async fn punch(controller: &mut FramedStream, key: &str, udp: &mut FramedSocket, offer: &str) -> Result<Option<PunchHole>> {
    let mut m = RendezvousMessage::new();
    m.set_punch_hole_request(PunchHoleRequest {
        id: TARGET.to_owned(),
        licence_key: key.to_owned(),
        nat_type: NatType::ASYMMETRIC.into(),
        webrtc_sdp_offer: offer.to_owned(),
        ..Default::default()
    });
    controller.send(&m).await?;
    Ok(match next_udp(udp, 3000).await {
        Some(rendezvous_message::Union::PunchHole(ph)) => Some(ph),
        _ => None,
    })
}

fn ice(id: &str, socket_addr: &[u8], key: &str, candidate: &str) -> RendezvousMessage {
    let mut m = RendezvousMessage::new();
    m.set_ice_candidate(IceCandidate {
        id: id.to_owned(),
        socket_addr: socket_addr.to_vec().into(),
        session_key: key.to_owned(),
        candidate: candidate.to_owned(),
        ..Default::default()
    });
    m
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() != 4 {
        bail!("usage: sec5_signal_probe <host-nonloopback> <port> <hbbs public key base64> <on|off>");
    }
    let (host, port, key, webrtc_on) = (a[0].clone(), a[1].parse::<u16>()?, a[2].clone(), a[3] == "on");
    let rs_pk = sign::PublicKey::from_slice(&hbb_common::base64::decode(&key)?).ok_or_else(|| anyhow!("bad key"))?;
    let server: SocketAddr = format!("{host}:{port}").parse()?;
    let mut all = true;

    // The target registers over UDP and stays online.
    let mut udp = FramedSocket::new("0.0.0.0:0").await?;
    let mut m = RendezvousMessage::new();
    m.set_register_peer(RegisterPeer { id: TARGET.to_owned(), serial: 0, ..Default::default() });
    udp.send(&m, server).await?;
    next_udp(&mut udp, 2000).await;
    let mut pk = RendezvousMessage::new();
    pk.set_register_pk(RegisterPk { id: TARGET.to_owned(), uuid: b"sec5-signal-probe".to_vec().into(), pk: vec![7u8; 32].into(), ..Default::default() });
    udp.send(&pk, server).await?;
    next_udp(&mut udp, 2000).await;
    udp.send(&m, server).await?;
    next_udp(&mut udp, 2000).await;

    // 1. The offer reaches the target (or is stripped when WebRTC is off).
    let mut controller = secured(&format!("127.0.0.1:{port}"), &rs_pk).await?;
    let ph = punch(&mut controller, &key, &mut udp, "OFFER-123").await?.ok_or_else(|| anyhow!("no PunchHole at the target"))?;
    if !webrtc_on {
        check(&mut all, "webrtc off: offer stripped", ph.webrtc_sdp_offer.is_empty(), format!("offer {:?}", ph.webrtc_sdp_offer));
        println!("{}", if all { "ALL PASS" } else { "SOME FAILED" });
        return Ok(());
    }
    check(&mut all, "offer forwarded to the target", ph.webrtc_sdp_offer == "OFFER-123", format!("got {:?}", ph.webrtc_sdp_offer));

    // 2. Relay route (production: ALWAYS_USE_RELAY): the answer rides on RelayResponse.
    let mut target = secured(&format!("{host}:{port}"), &rs_pk).await?;
    let mut rr = RendezvousMessage::new();
    rr.set_relay_response(RelayResponse {
        socket_addr: ph.socket_addr.clone(),
        uuid: "probe-uuid".to_owned(),
        relay_server: "relay.invalid".to_owned(),
        webrtc_sdp_answer: "ANSWER-456".to_owned(),
        ..Default::default()
    });
    target.send(&rr).await?;
    let got = match next_tcp(&mut controller, 3000).await {
        Some(rendezvous_message::Union::RelayResponse(r)) => r.webrtc_sdp_answer,
        other => format!("{other:?}"),
    };
    check(&mut all, "answer back to the controller (RelayResponse)", got == "ANSWER-456", format!("got {got:?}"));

    // 3. Candidates both ways; a wrong session key is dropped.
    controller.send(&ice(TARGET, &[], "SK-1", "C-from-controller")).await?;
    let got = match next_udp(&mut udp, 3000).await {
        Some(rendezvous_message::Union::IceCandidate(i)) => i.candidate,
        other => format!("{other:?}"),
    };
    check(&mut all, "controller candidate reaches the target", got == "C-from-controller", format!("got {got:?}"));
    // Like the client: the target's candidates go on a connection of their own (rendezvous_mediator).
    let mut target_ice = secured(&format!("{host}:{port}"), &rs_pk).await?;
    target_ice.send(&ice("", &ph.socket_addr, "SK-1", "C-from-target")).await?;
    let got = match next_tcp(&mut controller, 3000).await {
        Some(rendezvous_message::Union::IceCandidate(i)) => i.candidate,
        other => format!("{other:?}"),
    };
    check(&mut all, "target candidate reaches the controller", got == "C-from-target", format!("got {got:?}"));
    let mut intruder = secured(&format!("{host}:{port}"), &rs_pk).await?;
    intruder.send(&ice("", &ph.socket_addr, "SK-WRONG", "C-injected")).await?;
    let got = next_tcp(&mut controller, 1500).await;
    check(&mut all, "candidate with the wrong session key dropped", got.is_none(), format!("controller got {got:?}"));
    let closed = next_tcp(&mut intruder, 1500).await.is_none();
    check(&mut all, "and its connection closed", closed, String::new());

    // 4. Punch route: the answer rides on PunchHoleSent -> PunchHoleResponse.
    let mut controller2 = secured(&format!("127.0.0.1:{port}"), &rs_pk).await?;
    let ph2 = punch(&mut controller2, &key, &mut udp, "OFFER-789").await?.ok_or_else(|| anyhow!("no second PunchHole"))?;
    let mut sent = RendezvousMessage::new();
    sent.set_punch_hole_sent(PunchHoleSent {
        socket_addr: ph2.socket_addr.clone(),
        id: TARGET.to_owned(),
        webrtc_sdp_answer: "ANSWER-789".to_owned(),
        ..Default::default()
    });
    let mut target2 = secured(&format!("{host}:{port}"), &rs_pk).await?;
    target2.send(&sent).await?;
    let got = match next_tcp(&mut controller2, 3000).await {
        Some(rendezvous_message::Union::PunchHoleResponse(r)) => r.webrtc_sdp_answer,
        other => format!("{other:?}"),
    };
    check(&mut all, "answer back to the controller (PunchHoleResponse)", got == "ANSWER-789", format!("got {got:?}"));
    controller2.send(&ice(TARGET, &[], "SK-2", "C2")).await?;
    let got = matches!(next_udp(&mut udp, 3000).await, Some(rendezvous_message::Union::IceCandidate(_)));
    check(&mut all, "controller connection still open after the answer", got, String::new());

    println!("{}", if all { "ALL PASS" } else { "SOME FAILED" });
    Ok(())
}
