// Approved-device gate probe: the approved-device gate on hbbs.
// Usage: gate_probe <host-nonloopback> <hbbs_port> <licence_key> <approved_id>
// Registers <approved_id> over UDP from this machine's <host> address, then sends a
// PunchHoleRequest for it over TCP twice: from <host> (an approved device's address) and from
// 127.0.0.1 (not an approved device's address). A forwarded request shows up on the UDP socket
// (PunchHole or FetchLocalAddr); a blocked one is answered with ID_NOT_EXIST.
use hbb_common::{
    anyhow::{anyhow, Result},
    protobuf::Message as _,
    rendezvous_proto::*,
    tcp::FramedStream,
    tokio,
    udp::FramedSocket,
};
use std::net::SocketAddr;

async fn request(from: &str, port: u16, key: &str, id: &str, udp: &mut FramedSocket) -> Result<String> {
    let mut tcp = FramedStream::new(format!("{from}:{port}"), None, 3000).await?;
    let mut m = RendezvousMessage::new();
    m.set_punch_hole_request(PunchHoleRequest {
        id: id.to_owned(),
        licence_key: key.to_owned(),
        nat_type: NatType::ASYMMETRIC.into(),
        ..Default::default()
    });
    tcp.send(&m).await?;
    if let Some(Ok((b, _))) = udp.next_timeout(2000).await {
        return Ok(match RendezvousMessage::parse_from_bytes(&b)?.union {
            Some(rendezvous_message::Union::PunchHole(_)) => "forwarded (PunchHole)".into(),
            Some(rendezvous_message::Union::FetchLocalAddr(_)) => "forwarded (FetchLocalAddr)".into(),
            other => format!("udp got {other:?}"),
        });
    }
    match tcp.next_timeout(1000).await {
        Some(Ok(b)) => Ok(match RendezvousMessage::parse_from_bytes(&b)?.union {
            Some(rendezvous_message::Union::PunchHoleResponse(r)) => format!("refused ({:?})", r.failure.enum_value()),
            other => format!("tcp got {other:?}"),
        }),
        _ => Ok("no reply".into()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (host, port, key, id) = (a[0].clone(), a[1].parse::<u16>()?, a[2].clone(), a[3].clone());
    let server: SocketAddr = format!("{host}:{port}").parse()?;
    let mut udp = FramedSocket::new("0.0.0.0:0").await?;
    let mut m = RendezvousMessage::new();
    m.set_register_peer(RegisterPeer { id: id.clone(), serial: 0, ..Default::default() });
    udp.send(&m, server).await?;
    let reg = udp.next_timeout(2000).await.ok_or_else(|| anyhow!("no RegisterPeer reply"))??;
    println!("register {id}: {:?}", RendezvousMessage::parse_from_bytes(&reg.0)?.union.map(|_| "ok"));
    // A real client answers request_pk with its key; only then is it a known, online peer.
    let mut pk = RendezvousMessage::new();
    pk.set_register_pk(RegisterPk {
        id: id.clone(),
        uuid: b"sec4-gate-probe-uuid".to_vec().into(),
        pk: vec![7u8; 32].into(),
        ..Default::default()
    });
    udp.send(&pk, server).await?;
    let res = udp.next_timeout(2000).await.ok_or_else(|| anyhow!("no RegisterPk reply"))??;
    println!("register_pk: {:?}", RendezvousMessage::parse_from_bytes(&res.0)?.union);
    udp.send(&m, server).await?;
    udp.next_timeout(2000).await;
    println!("from {host} (approved address): {}", request(&host, port, &key, &id, &mut udp).await?);
    println!("from 127.0.0.1 (unapproved):    {}", request("127.0.0.1", port, &key, &id, &mut udp).await?);
    Ok(())
}
