// Asks hbbs which of the given IDs are currently registered (online), as a client's
// OnlineRequest does. Usage: online_peers <host:nat_port> <id>...
// <host> must NOT be loopback: hbbs treats loopback connections to its NAT port as the console.
use hbb_common::{protobuf::Message as _, rendezvous_proto::*, tcp::FramedStream, tokio};

#[tokio::main]
async fn main() -> hbb_common::ResultType<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let peers = a[1..].to_vec();
    let mut s = FramedStream::new(&a[0], None, 3000).await?;
    let mut m = RendezvousMessage::new();
    m.set_online_request(OnlineRequest {
        id: "sec3check".into(),
        peers: peers.clone(),
        ..Default::default()
    });
    s.send(&m).await?;
    let b = s.next_timeout(3000).await.ok_or_else(|| hbb_common::anyhow::anyhow!("no reply"))??;
    match RendezvousMessage::parse_from_bytes(&b)?.union {
        Some(rendezvous_message::Union::OnlineResponse(r)) => {
            for (i, p) in peers.iter().enumerate() {
                let on = r.states.get(i / 8).map_or(false, |x| x & (1 << (7 - i % 8)) != 0);
                println!("{p} {}", if on { "online" } else { "offline" });
            }
            Ok(())
        }
        other => hbb_common::bail!("unexpected reply {other:?}"),
    }
}
