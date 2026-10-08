> **This is a fork of [rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server)** —
> the official self-hosted RustDesk rendezvous (hbbs) and relay (hbbr) server, AGPL-3.0. Full credit
> to the RustDesk team and its contributors; the upstream history is preserved below the single
> commit this repository adds. It isn't a GitHub "fork" object only because this account's fork slot
> for rustdesk-server is used by
> [rustdesk-managed-directory-api](https://github.com/MAGA-Brad/rustdesk-managed-directory-api).
>
> It's the hardened hbbs/hbbr build that runs alongside
> [rustdesk-managed-directory-api](https://github.com/MAGA-Brad/rustdesk-managed-directory-api)
> ("RDS") and [rustdesk-managed-client](https://github.com/MAGA-Brad/rustdesk-managed-client)
> ("RDC"). It's a drop-in replacement for stock hbbs/hbbr and works with stock RustDesk clients;
> the approved-device gate, rendezvous encryption, WebRTC signaling and the device-passport check
> stay off until you turn them on.

## What this fork adds

### Message-size caps before a peer is trusted
Stock hbbs/hbbr accept very large messages from any connection before it has registered or paired.
That lets an unauthenticated client make the server allocate a lot of memory. This fork bounds
it:
- **hbbs:** every message on the rendezvous TCP, NAT-test and WebSocket listeners is capped at
  **64 KiB**. Registration, punch-hole and relay requests are tiny, so nothing a real client sends
  comes close.
- **hbbr, unpaired TCP:** a connection that hasn't been paired yet may send at most **64 KiB**,
  which is room for its relay request and nothing more. Once paired, the cap is lifted and the
  connection is forwarded raw as before.
- **hbbr, WebSocket:** connections are limited to **4 MiB frames / 16 MiB messages**.
  - These limits are set when the connection is accepted, because the bundled WebSocket library
    can't change them later.
  - The library also reserves a frame's declared length as soon as its header arrives, so these
    caps are what bound that reservation.

### WebSocket listeners can be bound separately (`WS_BIND`)
`WS_BIND` (or `--ws-bind`) gives the WebSocket listeners (hbbs 21118, hbbr 21119) their own bind
address. Set it to `127.0.0.1` when a local TLS reverse proxy (for example Caddy serving
`wss://…/ws/id` and `/ws/relay`) is the only thing that should reach them. The plain TCP/UDP
listeners keep the general bind address. Unset, behaviour is unchanged.

### Optional approved-device gate (`APPROVED_GATE`)
- **What it does.** It lets only devices on an allow-list *start* a connection (punch-hole or relay
  request).
- **How a request is attributed.** hbbs is never told who is asking, since those requests carry
  only the target ID. So a request counts as approved if it comes from an address that an
  approved device registered from within the last 30 seconds.
- **Settings:**
  - `APPROVED_GATE`: `off` (default), `log` (allow, but log what would be blocked), or `enforce`.
  - `APPROVED_IDS_FILE`: one RustDesk ID per line. It's re-read every 15 seconds and considered
    stale after 10 minutes. RDS ships a small export script that keeps it in sync.
- **Fails open.** A missing, empty or stale list lets everything through with a warning, so a
  broken sync can't lock out the fleet.
- **This is the coarse outer layer.** Address-based attribution can't be exact behind
  carrier-grade NAT or shared networks. The strict boundary is the managed client's own
  device-certificate check on every login (see the
  [client README](https://github.com/MAGA-Brad/rustdesk-managed-client#security-model)).

### Rendezvous encryption: a signed key exchange on every TCP and WebSocket connection
- **What it does.** hbbs opens each rendezvous connection with a key exchange: an ephemeral X25519
  public key signed with the server's key, plus signed parameters so the protocol version can't be
  lowered on the way. A client that takes part answers with its own key and the session key, and
  everything after that is encrypted. This is the server half of the client's existing
  `secure_tcp`, so stock clients that already support it get encryption too. WebSocket connections
  run the same exchange inside the WebSocket, so a client that fell back to it (for example
  through a CDN on port 443) doesn't depend on whatever terminates TLS in front of hbbs for the
  server's identity.
- **Modes:**
  - `off` (default): no key exchange, stock behaviour.
  - `optional`: clients that do the exchange are encrypted; clients that don't skip the first
    message and continue in the clear.
  - `required`: unencrypted clients are refused, and so is the original version-0 scheme, which
    uses one key in both directions.

  The exchange needs hbbs's private key (the normal setup); an hbbs started with only a public
  key skips it in every mode. Managed clients from
  [rustdesk-managed-client](https://github.com/MAGA-Brad/rustdesk-managed-client) build 30 on
  require the exchange, so they need `optional` or `required` (RDS refuses to switch it off while
  any approved client reports build 30 or newer).
- **Where the mode comes from.** `rendezvous-encryption=<mode>` in the settings file below, else
  `RENDEZVOUS_ENCRYPTION`, else off. Every 5 minutes hbbs writes how connections arrived (current
  scheme, version 0, unencrypted, failed) to `rendezvous_stats` in its working directory, and logs
  them unless the mode is off, so you can see what `required` would refuse before switching to it.
- **Not covered:** UDP registration and the NAT-test port (21115). Online-status queries can now be
  asked on the key-exchanged connections instead (next section).

### Online status on the key-exchanged connection
- **What it does.** hbbs also answers `OnlineRequest` on its main TCP and WebSocket listeners
  (after the key exchange, when encryption is on), so clients can ask over their encrypted
  connection (and its 443 fallback) instead of port 21115, which some networks block. Managed
  clients from build 34 ask this way.
- **Only approved devices get an answer here.** The request names the asking device's own ID, which
  must be on the approved list (`APPROVED_IDS_FILE`, as for the gate above). Anyone else gets
  nothing, so these listeners can't be used to probe which IDs exist; if the list is unavailable,
  nobody gets an answer, which only empties the online marks.
- **The connection stays open** after an answer, so a client can ask again on it; an idle one still
  ends after the 30-second read timeout. Port 21115 keeps answering anyone, as upstream does, for
  stock clients (the reference deployment gates that port with relay-access leases).

### Device passports (`passport`)
- **What it does.** Right after the key exchange, a managed client (build 34 on) can prove which
  device it is: it sends its passport, issued by the CA that
  [rustdesk-managed-directory-api](https://github.com/MAGA-Brad/rustdesk-managed-directory-api)
  runs on a separate VM, plus a signature with its identity key over this connection's key
  exchange (hbbs's signing key, both ephemeral keys and the version). A recorded proof doesn't fit
  any other connection. hbbs offers this through a capability flag in its signed key-exchange
  parameters (`KxParams.managed_capabilities`, value 1, the lowest bit); clients that don't know it
  ignore it.
- **What hbbs checks.** The passport must chain to a CA root hbbs was started with
  (`PASSPORT_ROOTS`, base64url, comma-separated; from the host's own configuration, never from
  RDS), be within its validity window (10 minutes of clock skew allowed), name an approved ID, and
  carry the identity key RDS lists for that ID (`APPROVED_KEYS_FILE`, default `approved_keys` in
  the working directory, `id fingerprint` per line, written by RDS's sync). RDS decides that key
  itself (it verifies key updates and refuses CA results for any other key), so the CA alone can't
  make or re-key a device. A passport that expired recently is accepted for `passport-grace-days`
  (default 7, at most 30), but only while the approved list is available. Like the gate, the approved-ID check fails open: with no current
  list, a valid passport whose key is in `approved_keys` is accepted (that file is kept, with a
  warning, when it stops updating).
- **Modes** (`passport` in the settings file):
  - `off` (default): not offered, stock behaviour.
  - `log`: count proven and unproven requests, refuse nothing.
  - `test`: refuse unproven requests only when a device listed in `passport-test-ids` is involved,
    as the target or as the device the message speaks for.
  - `enforce`: refuse every punch-hole request, relay request, reply (relay response, punch-hole
    sent, local address) and online query that the connection's proven device can't back.

  A reply that carries no ID (a WebRTC answer) on a proven connection counts as that device's.
  Every 5 minutes hbbs logs the counts and writes them to `passport_stats` in its working
  directory, so you can see what `test` or `enforce` would refuse before switching.
- **Not covered yet:** registration (still UDP) and connections to hbbr.

### WebRTC signaling through hbbs
- **What it does.** hbbs forwards a controller's WebRTC offer (inside its connection request), the
  target's answer, and both sides' ICE candidates, so two clients can try a direct WebRTC path while
  the relay stays the fallback. Offers go through only inside a connection request hbbs let through
  (the approved-device gate applies), and only over TCP: an offer that arrives over WebSocket is
  dropped.
- **Switch.** Off unless `webrtc=on`, or `webrtc=test` with the target listed in `webrtc-test-ids`
  (settings file below, else `WEBRTC` / `WEBRTC_TEST_IDS`). Otherwise hbbs drops offers and clients
  use their usual route. The switch lives in hbbs because `ALWAYS_USE_RELAY` doesn't stop WebRTC on
  the client, and a client answers an offer using its own STUN servers, so `test` keeps WebRTC to
  clients you've built with your own STUN list.
- **Limits.** A signaling session is keyed by the controller's address and lasts 60 seconds (4096
  at most at once). The first session key seen is pinned, each direction gets at most 64
  candidates, and anything else is dropped.
- **hbbs only routes.** The managed client seals the offer, answer and candidates end to end, so
  hbbs can't read them (see the
  [client README](https://github.com/MAGA-Brad/rustdesk-managed-client#security-model)).

### Settings RDS controls without a restart (`rendezvous_settings`)
A `key=value` file in hbbs's working directory, written every minute by RDS's sync timer from its
Config page (`rendezvous-encryption`, `webrtc`, `webrtc-test-ids`, `passport`, `passport-test-ids`,
`passport-grace-days`). hbbs re-reads it at most every 15 seconds and logs each change; a key the
file doesn't have falls back to the environment. The CA roots are deliberately not among them.

### Build and maintenance changes
- **hbb_common:** updated to a current upstream commit. Its `IdPk` type moved into
  `rendezvous_proto`, and the server code is adjusted to match. The submodule points at
  [MAGA-Brad/hbb_common](https://github.com/MAGA-Brad/hbb_common/tree/managed-relay), branch
  `managed-relay`: that upstream commit plus one commit adding the passport message
  (`KxParams.managed_capabilities` and `DeviceAuth`, field number 101 in both).
- **`libs/rdc-passport`:** the passport format and checks, shared with the CA signer (the same
  crate is in rustdesk-managed-directory-api under `directory-api/ca/passport`).
- **Static Linux builds:** OpenSSL is vendored (built from source), so a static musl build works
  without a system OpenSSL.

### Probes for verifying a deployment
`examples/` contains small tools that check a running server from another machine. They target a
non-loopback address, because hbbs and hbbr treat loopback connections as the admin console.
- **`sec3_probe`:** checks a running hbbs/hbbr pair over TCP and WebSocket:
  - the NAT-test and online-query replies;
  - that oversized messages are refused on each listener;
  - multi-MiB relay transfers over TCP+TCP, TCP+WebSocket and WebSocket+WebSocket pairings, which
    confirms the cap is lifted once a connection is paired.
- **`gate_probe`:** checks the approved-device gate from an approved device's address and from a
  non-approved one.
- **`online_peers`:** asks hbbs which IDs are currently registered, the same way a client's online
  query does.
- **`sec5_kx_probe`:** plays a current client (version 1), a legacy client (version 0), a client
  that skips the key exchange and a malformed reply, and checks each outcome against what the
  `optional` or `required` mode should allow.
- **`sec5_signal_probe`:** plays both a controller and a target and checks that offers, answers and
  candidates are forwarded (or dropped) as the WebRTC switch says, over key-exchanged
  connections.
- **`sec6_kx_probe`:** the same key-exchange cases as `sec5_kx_probe`, over TCP or a `ws(s)://`
  URL of hbbs's WebSocket.
- **`sec7_online_probe`:** asks for online states on hbbs's main listener after the key exchange,
  the way managed clients do; the asking ID must be on the approved list.
- **`sec8_devauth_probe`:** `setup` writes a test CA root and matching approved lists; each case
  then sends a DeviceAuth (valid, expired, in grace, wrong root, wrong key, not approved,
  malformed, replayed from another connection, and more) and reports whether hbbs answered or
  refused. It uses fixed test keys only.

Run one with: `cargo run --example <name> -- <args>`. The usage line at the top of each file lists
its arguments.

---

Everything below is the upstream rustdesk-server README, unmodified.

---

# RustDesk Server Program

[![build](https://github.com/rustdesk/rustdesk-server/actions/workflows/build.yaml/badge.svg)](https://github.com/rustdesk/rustdesk-server/actions/workflows/build.yaml)

[**Download**](https://github.com/rustdesk/rustdesk-server/releases)

[**Manual**](https://rustdesk.com/docs/en/self-host/)

[**Configuration & environment variables**](docs/environment-variables.md)

[**FAQ**](https://github.com/rustdesk/rustdesk/wiki/FAQ)

[**How to migrate OSS to Pro**](https://rustdesk.com/docs/en/self-host/rustdesk-server-pro/installscript/#convert-from-open-source)

Self-host your own RustDesk server, it is free and open source.

> [!IMPORTANT]
> **Need more features?** [RustDesk Server Pro](https://rustdesk.com/pricing.html) might suit you better.
>
> **Want to develop your own server?** Start with [rustdesk-server-demo](https://github.com/rustdesk/rustdesk-server-demo), a simpler starting point than this repository.

## How to build manually

```bash
cargo build --release
```

Three executables will be generated in target/release.

- hbbs - RustDesk ID/Rendezvous server
- hbbr - RustDesk relay server
- rustdesk-utils - RustDesk CLI utilities

You can find updated binaries on the [Releases](https://github.com/rustdesk/rustdesk-server/releases) page.

## Configuration

`hbbs` and `hbbr` can be configured with command-line flags, environment
variables, or an `.env` / config file. Run `hbbs --help` or `hbbr --help` to see
the available flags.

The most common options:

| Option | Flag | Env var | Applies to | Purpose |
| --- | --- | --- | --- | --- |
| Key | `-k` | `KEY` | hbbs, hbbr | `hbbs` loads/generates one by default |
| Bind address | `-b` | `BIND` | hbbs, hbbr | Local IP address to listen on (default: all interfaces; requires 1.1.17+) |
| Port | `-p` | `PORT` | hbbs, hbbr | Listening port (hbbs `21116`, hbbr `21117`) |
| Relay servers | `-r` | `RELAY-SERVERS` | hbbs | Override when the relay uses a different address or a non-standard port |
| Force relay | — | `ALWAYS_USE_RELAY` | hbbs | `Y` disables direct connections |
| Log level | — | `RUST_LOG` | hbbs, hbbr | e.g. `debug` (default `info`) |

See **[docs/environment-variables.md](docs/environment-variables.md)** for the
full list of variables, the file/flag/env precedence rules, database and relay
bandwidth tuning, Docker image variables, and examples.

## Installation

Please follow this [doc](https://rustdesk.com/docs/en/self-host/rustdesk-server-oss/)
