// Hardening probe: functional and message-cap checks against a running hbbs/hbbr pair.
// Usage: sec3_probe <host> <hbbs_port> <hbbr_port> <relay_key> [ws_host]
// <host> must NOT be loopback: hbbs's NAT port and hbbr's TCP port treat loopback connections
// as the admin console. WebSocket listeners may be loopback-only (WS_BIND), hence ws_host.
// (NAT-test port = hbbs_port - 1, WebSocket ports = hbbs_port + 2 / hbbr_port + 2)
use hbb_common::{
    anyhow::{anyhow, bail, Result},
    futures_util::{SinkExt, StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tcp::FramedStream,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        time::{sleep, timeout, Duration},
    },
};
use tungstenite::Message as WsMsg;

fn header(n: usize) -> Vec<u8> {
    // BytesCodec length prefix: low 2 bits = header length - 1, length in the rest, little-endian.
    let v = n << 2;
    if n <= 0x3F {
        vec![v as u8]
    } else if n <= 0x3FFF {
        ((v | 1) as u16).to_le_bytes().to_vec()
    } else if n <= 0x3F_FFFF {
        ((v | 2) as u32).to_le_bytes()[..3].to_vec()
    } else {
        ((v | 3) as u32).to_le_bytes().to_vec()
    }
}

fn request_relay(uuid: &str, key: &str) -> Vec<u8> {
    let mut m = RendezvousMessage::new();
    m.set_request_relay(RequestRelay {
        uuid: uuid.to_owned(),
        licence_key: key.to_owned(),
        ..Default::default()
    });
    m.write_to_bytes().unwrap()
}

fn test_nat() -> RendezvousMessage {
    let mut m = RendezvousMessage::new();
    m.set_test_nat_request(TestNatRequest { serial: 1, ..Default::default() });
    m
}

/// Sends only a length header claiming `claimed` bytes, then expects the server to drop the
/// connection at once instead of waiting for (and buffering) the claimed payload.
async fn closes_on_oversize_header(addr: &str, claimed: usize) -> Result<()> {
    let mut s = TcpStream::connect(addr).await?;
    s.write_all(&header(claimed)).await?;
    s.write_all(&[0u8; 16]).await?;
    let mut buf = [0u8; 64];
    match timeout(Duration::from_secs(3), s.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => Ok(()),
        Ok(Ok(n)) => bail!("server answered {n} bytes instead of closing"),
        Err(_) => bail!("server kept the connection open waiting for the payload"),
    }
}

async fn hbbs_tcp_testnat(addr: &str) -> Result<()> {
    let mut s = FramedStream::new(addr, None, 3000).await?;
    s.send(&test_nat()).await?;
    let b = s.next_timeout(3000).await.ok_or_else(|| anyhow!("no reply"))??;
    match RendezvousMessage::parse_from_bytes(&b)?.union {
        Some(rendezvous_message::Union::TestNatResponse(_)) => Ok(()),
        other => bail!("unexpected reply {other:?}"),
    }
}

async fn hbbs_nat_online(addr: &str) -> Result<()> {
    let mut s = FramedStream::new(addr, None, 3000).await?;
    let mut m = RendezvousMessage::new();
    m.set_online_request(OnlineRequest {
        id: "sec3probe".into(),
        peers: vec!["123456789".into()],
        ..Default::default()
    });
    s.send(&m).await?;
    let b = s.next_timeout(3000).await.ok_or_else(|| anyhow!("no reply"))??;
    match RendezvousMessage::parse_from_bytes(&b)?.union {
        Some(rendezvous_message::Union::OnlineResponse(_)) => Ok(()),
        other => bail!("unexpected reply {other:?}"),
    }
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn ws_connect(url: &str) -> Result<Ws> {
    // The client side may send up to 64 MiB so the server's own limit is what gets tested.
    let cfg = tungstenite::protocol::WebSocketConfig {
        max_message_size: Some(64 << 20),
        max_frame_size: Some(64 << 20),
        ..Default::default()
    };
    Ok(tokio_tungstenite::connect_async_with_config(url, Some(cfg)).await?.0)
}

async fn ws_closed(ws: &mut Ws) -> bool {
    match timeout(Duration::from_secs(3), ws.next()).await {
        Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(WsMsg::Close(_)))) => true,
        _ => false,
    }
}

async fn hbbs_ws_testnat(url: &str) -> Result<()> {
    let mut ws = ws_connect(url).await?;
    ws.send(WsMsg::Binary(test_nat().write_to_bytes()?)).await?;
    loop {
        match timeout(Duration::from_secs(3), ws.next()).await {
            Ok(Some(Ok(WsMsg::Binary(b)))) => {
                return match RendezvousMessage::parse_from_bytes(&b)?.union {
                    Some(rendezvous_message::Union::TestNatResponse(_)) => Ok(()),
                    other => bail!("unexpected reply {other:?}"),
                }
            }
            Ok(Some(Ok(_))) => continue,
            other => bail!("no reply: {other:?}"),
        }
    }
}

async fn ws_oversize_closed(url: &str, size: usize) -> Result<()> {
    let mut ws = ws_connect(url).await?;
    let _ = ws.send(WsMsg::Binary(vec![7u8; size])).await;
    if ws_closed(&mut ws).await {
        Ok(())
    } else {
        bail!("server accepted a {size}-byte message")
    }
}

/// A connects and waits; B connects with the same uuid and gets paired; then a `size`-byte
/// message goes A -> B and another B -> A. Both ends here keep the codec framing, as the real
/// clients do; hbbr forwards raw (TCP+TCP) or re-frames (any WebSocket end).
async fn relay_pair(host: &str, ws_host: &str, port: u16, key: &str, a_ws: bool, b_ws: bool, size: usize) -> Result<()> {
    enum End {
        Tcp(FramedStream),
        Ws(Ws),
    }
    async fn open(host: &str, ws_host: &str, port: u16, ws: bool, hello: Vec<u8>) -> Result<End> {
        if ws {
            let mut w = ws_connect(&format!("ws://{ws_host}:{}", port + 2)).await?;
            w.send(WsMsg::Binary(hello)).await?;
            Ok(End::Ws(w))
        } else {
            let mut t = FramedStream::new(format!("{host}:{port}"), None, 3000).await?;
            t.send_raw(hello).await?;
            Ok(End::Tcp(t))
        }
    }
    async fn send(e: &mut End, data: Vec<u8>) -> Result<()> {
        match e {
            End::Tcp(t) => t.send_raw(data).await,
            End::Ws(w) => Ok(w.send(WsMsg::Binary(data)).await?),
        }
    }
    async fn recv(e: &mut End, want: usize) -> Result<usize> {
        let mut got = 0;
        while got < want {
            let n = match e {
                End::Tcp(t) => t.next_timeout(10_000).await.ok_or_else(|| anyhow!("timeout"))??.len(),
                End::Ws(w) => match timeout(Duration::from_secs(10), w.next()).await {
                    Ok(Some(Ok(WsMsg::Binary(b)))) => b.len(),
                    Ok(Some(Ok(_))) => 0,
                    other => bail!("ws ended: {other:?}"),
                },
            };
            got += n;
        }
        Ok(got)
    }
    let uuid = format!("sec3-{}-{}-{}", a_ws, b_ws, size);
    let mut a = open(host, ws_host, port, a_ws, request_relay(&uuid, key)).await?;
    sleep(Duration::from_millis(300)).await;
    let mut b = open(host, ws_host, port, b_ws, request_relay(&uuid, key)).await?;
    sleep(Duration::from_millis(300)).await;
    let payload = vec![0x5Au8; size];
    send(&mut a, payload.clone()).await?;
    let got = recv(&mut b, size).await?;
    send(&mut b, payload).await?;
    let back = recv(&mut a, size).await?;
    if got == size && back == size {
        Ok(())
    } else {
        bail!("forwarded {got}/{back} of {size} bytes")
    }
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let host = a.get(1).cloned().unwrap_or_else(|| "127.0.0.1".into());
    let hbbs: u16 = a.get(2).and_then(|x| x.parse().ok()).unwrap_or(21116);
    let hbbr: u16 = a.get(3).and_then(|x| x.parse().ok()).unwrap_or(21117);
    let key = a.get(4).cloned().unwrap_or_default();
    let ws_host = a.get(5).cloned().unwrap_or_else(|| host.clone());
    let s = format!("{host}:{hbbs}");
    let nat = format!("{host}:{}", hbbs - 1);
    let r = format!("{host}:{hbbr}");
    let s_ws = format!("ws://{ws_host}:{}", hbbs + 2);
    let r_ws = format!("ws://{ws_host}:{}", hbbr + 2);
    let mib = 1 << 20;
    let tests: Vec<(&str, Result<()>)> = vec![
        ("hbbs TCP: TestNat request answered", hbbs_tcp_testnat(&s).await),
        ("hbbs NAT port: Online request answered", hbbs_nat_online(&nat).await),
        ("hbbs TCP: 1 MiB header refused at once", closes_on_oversize_header(&s, mib).await),
        ("hbbs NAT port: 1 MiB header refused at once", closes_on_oversize_header(&nat, mib).await),
        ("hbbs WS: TestNat request answered", hbbs_ws_testnat(&s_ws).await),
        ("hbbs WS: 100 KiB message refused", ws_oversize_closed(&s_ws, 100 * 1024).await),
        ("hbbr TCP: unpaired 1 MiB header refused at once", closes_on_oversize_header(&r, mib).await),
        ("hbbr WS: unpaired 6 MiB message refused", ws_oversize_closed(&r_ws, 6 * mib).await),
        ("hbbr TCP+TCP pair: 2 MiB each way", relay_pair(&host, &ws_host, hbbr, &key, false, false, 2 * mib).await),
        ("hbbr TCP+WS pair: 2 MiB each way (cap lifted)", relay_pair(&host, &ws_host, hbbr, &key, false, true, 2 * mib).await),
        ("hbbr WS+WS pair: 3 MiB each way", relay_pair(&host, &ws_host, hbbr, &key, true, true, 3 * mib).await),
    ];
    let mut failed = 0;
    for (name, res) in tests {
        match res {
            Ok(()) => println!("PASS  {name}"),
            Err(e) => {
                failed += 1;
                println!("FAIL  {name}: {e}");
            }
        }
    }
    println!("{} passed, {failed} failed", 11 - failed);
    std::process::exit(if failed == 0 { 0 } else { 1 });
}
