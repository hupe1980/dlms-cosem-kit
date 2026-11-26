# Changelog

Notable changes, newest first. The format follows [Keep a Changelog], and versions follow
[Semantic Versioning] — with the pre-1.0 rule that **the minor version is the breaking
one**.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

## [0.3.0] — 2026-11-26

- Added `Client::get_into` for ordinary and selected GETs that borrow caller storage.
- **Breaking:** `with_response_capacity` limits the encoded result across ordinary GET,
  GET lists, ACTION returns and both block mechanisms. In 0.2.0 it sized the decryption
  and GBT workspace, leaving service-block accumulation uncapped.
  `ClientError::ResponseTooLarge` reports the effective limit and whether to reconnect.
- **Breaking:** `ProfileBuffer::for_each_cell` rejects a row wider than its capture list
  before its first callback. Valid shortened rows still inherit trailing values.
- The meter example accepts a loopback port. Pass `0` for an available port.

## [0.2.0] — 2026-11-22

### Added

- **General block transfer, chosen by both engines.** When the association negotiates
  `general-block-transfer` (now in both default conformance blocks), a reply too large for
  the client goes out as GBT for *every* service — ACCESS and the list forms included — and
  a long request may arrive as GBT. The whole APDU is protected once and verified once, on
  the reassembled bytes. `Server::poll_block` yields the rest of a streamed window;
  `ClientSession::handle_response` gathers blocks into the caller's buffer and answers
  `Response::Pending` / `Response::Acknowledge(GbtAck)`. A broken window asks for its retry
  once. `ServerConfig::gbt_window`, `ClientConfig::gbt_window`.
- `GbtSendCursor` / `GbtRecvCursor`: the GBT procedure without a borrowed buffer, so it
  can be stored beside the bytes.
- **`client::Client`** (`std`): a blocking driver over a two-method `Transport` —
  association with high level security, `get`, `get_selected`, `get_list`, `read_scaled`,
  `set`, `action`, `release` — with both block mechanisms in both directions, owned
  `DataBuf` values and one `ClientError`.
- **`transport::WrapperTransport`** (TCP) and **`transport::HdlcTransport`** (any
  `Read + Write`), with a 30-second default timeout.
- **`security::OsRandom`** and `RustCryptoProvider::os(keys)` (`std`): the operating
  system's randomness for HLS challenges, via `getrandom`. The examples no longer ship a
  counter in its place.
- `DataBuf` accessors (`as_i64`, `as_u64`, `as_bool`, `as_bytes`, `as_str`, `as_array`,
  `as_structure`, `as_datetime`, `as_obis`) and a readable `Display`.
- `hdlc::Reassembler::{resume, state}` and `ReassemblyState`, for a driver that owns the
  storage.
- A `client_response` fuzz target, and `tests/layering.rs`, which fails if `cosem` names
  `xdlms` again.

### Changed (breaking)

- `client::Response` gains `Pending`, `Acknowledge` and `BlocksAcked`.
- `ServerConfig` and `ClientConfig` gain `gbt_window`.
- `Server::handle` may return `Ok(0)`: nothing to send.
- `Conformance::CLIENT_DEFAULT` and `SERVER_DEFAULT` include `GENERAL_BLOCK_TRANSFER`, so
  two peers on the defaults answer large reads with GBT rather than service-level blocks.
  Clear the bit to keep the old behaviour.
- `SelectiveAccess` lives in `cosem` (re-exported from `xdlms`), so the object model no
  longer depends on the application layer.
- `GbtReceiver` acknowledges when the sender's streaming bit is clear or its own window
  fills, rather than counting the sender's window — the reading that cannot deadlock.

## [0.1.0] — 2026-11-22

Published as `dlms-cosem-rs` and, renamed, as `dlms-cosem-kit`.

### Added

- **Codec** — bounds-checked cursor, `Encode`/`Decode`, every error carrying the byte
  offset it happened at.
- **A-XDR** — borrowed `Data<'a>`, compact arrays with a bounded work budget, the
  edition-10 delta types, COSEM date/time with wildcards, units and scaled values; owned
  `DataBuf` behind `alloc`.
- **ACSE** — AARQ/AARE/RLRQ/RLRE, application contexts, authentication mechanisms, the
  24-bit conformance block.
- **xDLMS** — every APDU tag; GET, SET, ACTION and ACCESS with every `with-list` form;
  block transfer in both directions; general block transfer with the edition-9 streaming
  window and retry sub-procedure; push; exceptions.
- **Short-name referencing** behind the `sn` feature (off by default) — Read, Write,
  UnconfirmedWrite and InformationReport, driven from both engines, dispatched through the
  same object store and access control as the logical-name services.
- **Security** — suites 0–2 at both key widths, `glo-`/`ded-`/`general-glo-` ciphering,
  `general-ciphering` in its identified-key form, AES key wrap under 128- and 256-bit
  key-encrypting keys, HLS-GMAC, invocation counters and a per-peer replay window, all
  behind a swappable `CryptoProvider`.
- **Object model** — 102 interface classes as a registry, OBIS, access rights in both
  shapes, profile selective access, profile buffers with all three compressions undone.
- **Engines** — sans-I/O `ClientSession` and `Server`, a `NotificationListener` and a
  `PushSender`.
- **Transports** — HDLC (framing, addressing, segmentation and a link machine), the
  TCP/UDP wrapper, and the P1 customer interface.

### Security

- The **key set** an incoming frame is opened under comes from this end's policy, never
  from the frame's own broadcast bit or `glo-`/`ded-` tag.
- The **replay window** belongs to a peer rather than to an association: it survives
  `Server::reset`, so a client that reconnects cannot replay what it sent before the gap.
- A **new AARQ** clears everything scoped to the previous association, so a second
  association cannot inherit its dedicated key.
- A server whose provider cannot hold a delivered **dedicated key** refuses the
  association instead of continuing on the global key set.
- A stale **invocation counter** is answered `invocation-counter-error` at the AARQ, where
  a ciphered association actually fails first, carrying the value to move to.

### Not built

The CoAP transport; reliable (confirmed) push and push scheduling; SMS, M-Bus, mode E and
gateway routing; the asymmetric halves of suites 1 and 2; HLS mechanisms 3, 4, 6 and 7;
`action-request-with-list-and-first-pblock`. Each is refused by name rather than guessed
at — see [the status page](https://hupe1980.github.io/dlms-cosem-kit/docs/status/).

**Interoperability has not been tested.** Almost every green test is this crate agreeing
with itself.

[0.3.0]: https://github.com/hupe1980/dlms-cosem-kit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/hupe1980/dlms-cosem-kit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hupe1980/dlms-cosem-kit/releases/tag/v0.1.0
