# dlms-cosem-kit

**DLMS/COSEM (IEC 62056) in one Rust crate: sans-I/O, `no_std`, client *and* server.**

[![crates.io](https://img.shields.io/crates/v/dlms-cosem-kit.svg)](https://crates.io/crates/dlms-cosem-kit)
[![docs.rs](https://img.shields.io/docsrs/dlms-cosem-kit)](https://docs.rs/dlms-cosem-kit)
[![license](https://img.shields.io/crates/l/dlms-cosem-kit.svg)](#license)

**[Documentation and guides →](https://hupe1980.github.io/dlms-cosem-kit/)**

The protocol a smart electricity, gas, water or heat meter speaks to the system that
reads it — the object model, the application layer and the transports — with no sockets,
no clock and no async runtime in the core. The same code drives a head-end under Tokio,
a WASM decoder in a browser, and a meter or gateway on a Cortex-M under Embassy.

```rust
use dlms_cosem_kit::client::{Client, ClientConfig};
use dlms_cosem_kit::obis::Obis;
use dlms_cosem_kit::security::{KeyRing, RustCryptoProvider};
use dlms_cosem_kit::xdlms::AttributeDescriptor;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// let link = dlms_cosem_kit::transport::WrapperTransport::connect("10.0.0.5:4059", 0x10, 0x01)?;
# let link = doctest_meter();
let mut meter: Client<_, _> =
    Client::connect(link, ClientConfig::default(), RustCryptoProvider::os(KeyRing::default()))?;

// Class 3 is Register: its value with its scaler and unit, in one round trip.
let energy = meter.read_scaled(3, Obis::new(1, 0, 1, 8, 0, 255))?;
println!("{energy}"); // 12345678 Wh

// A load profile far larger than one APDU arrives whole: block transfer and general block
// transfer, in either direction, happen inside the call.
let profile = meter.get(AttributeDescriptor::new(7, Obis::new(1, 0, 99, 1, 0, 255), 2))?;
# let _ = profile;
meter.release()?;
# Ok(())
# }
#
# // A one-register meter in the same process, standing in for the socket.
# use dlms_cosem_kit::axdr::Data;
# use dlms_cosem_kit::client::Transport;
# use dlms_cosem_kit::codec::{Encode, Writer};
# use dlms_cosem_kit::cosem::AttributeAccess;
# use dlms_cosem_kit::server::{ObjectStore, Server, ServerConfig, StoreResult};
# use dlms_cosem_kit::xdlms::{DataAccessResult, SelectiveAccess};
# struct OneRegister;
# impl ObjectStore for OneRegister {
#     fn get_attribute(&self, _c: u16, _n: Obis, a: i8, _s: Option<SelectiveAccess<'_>>, w: &mut dyn Writer) -> StoreResult<()> {
#         let bad = |_| DataAccessResult::OtherReason;
#         // Attribute 3 is the scaler and unit: 10^0, Wh.
#         if a == 3 { return w.write_bytes(&[0x02, 0x02, 0x0F, 0x00, 0x16, 0x1E]).map_err(bad) }
#         Data::DoubleLongUnsigned(12_345_678).encode(w).map_err(bad)
#     }
#     fn attribute_access(&self, _c: u16, _n: Obis, _a: i8) -> AttributeAccess { AttributeAccess::READ }
# }
# struct Loopback(Server<OneRegister, RustCryptoProvider>, Vec<Vec<u8>>);
# impl Transport for Loopback {
#     fn send(&mut self, apdu: &[u8]) -> std::io::Result<()> {
#         let mut out = [0u8; 1024];
#         let n = self.0.handle(apdu, &mut out).map_err(std::io::Error::other)?;
#         self.1.push(out[..n].to_vec());
#         Ok(())
#     }
#     fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
#         let a = self.1.remove(0);
#         buf[..a.len()].copy_from_slice(&a);
#         Ok(a.len())
#     }
# }
# fn doctest_meter() -> Loopback {
#     Loopback(Server::new(ServerConfig::default(), OneRegister, RustCryptoProvider::new(KeyRing::default())), Vec::new())
# }
```

`Client` is the blocking driver, for a head-end or a tool. Underneath it is
[`client::ClientSession`], which is sans-I/O — bytes out, bytes in, no socket — and is what
runs in firmware, under an async runtime, or in a unit test:

```rust,ignore
let n = session.associate_request(&mut request)?;      // send request[..n] however you like
let step = session.handle_associate_response(&reply)?; // and feed the answer back
```

## What is here

| Layer | What it does |
|---|---|
| [`codec`] | A bounds-checked cursor. Every error carries the **byte offset** it happened at. |
| [`axdr`] | `Data` borrowed from the input — a load profile decodes without allocating. Compact arrays, delta types, COSEM date-times with their wildcards intact. |
| [`ber`], [`acse`] | AARQ / AARE / RLRQ / RLRE: application context, authentication mechanism, system titles, conformance. |
| [`xdlms`] | Every APDU tag. GET / SET / ACTION / ACCESS, block transfer, general block transfer with its streaming window and retry, push, exceptions, the four protection wrappers, and short-name Read / Write behind the `sn` feature. |
| [`security`] | `glo-`/`ded-`/general ciphering under suites 0–2 at both key widths, HLS-GMAC, invocation counters with a real replay window, AES key wrap — all behind a swappable [`security::CryptoProvider`], which is the one place keys live. |
| [`cosem`] | Interface classes as a registry, OBIS, access rights in both the legacy and version-3 shapes, profile selective access, and profile buffers with all three compressions undone. |
| [`transport`] | HDLC with a resynchronising frame finder, segmentation, and a link machine that drives SNRM/UA and the sequence numbers; the TCP/UDP wrapper with bounded reassembly; **P1** — DSMR and eMUCs telegrams, with exact decimals rather than floats. |
| [`client`], [`server`] | Sans-I/O state machines with block transfer in both directions — the service-level forms and **general block transfer, which both engines choose and drive themselves** — every batched service, ACCESS, both referencing modes, and both halves of push. With `std`, a blocking [`client::Client`] driver over the shipped wrapper/TCP and HDLC transports. |

## Why another one

- **MIT or Apache-2.0.** The reference implementation is GPL-2 or commercial.
- **`no_std`, `alloc` optional.** Codec, HDLC, the wrapper, both engines and suite 0 build
  for `thumbv7em-none-eabihf` with no allocator.
- **Sans-I/O.** A whole ciphered association runs as a unit test in microseconds.
- **Client and server from one object model.** [`cosem`] does not depend on [`xdlms`].
- **Panic-free from the network.** `#![forbid(unsafe_code)]`, and CI fails if a bare-metal
  release build contains a single panic symbol.
- **Replay rejected.** An invocation counter is never accepted twice — client, server and
  push listener alike.
- **Keys in one place.** A [`security::CryptoProvider`]; the default zeroises and never
  prints them, a secure element is another implementation.

## Decrypting a meter's push

A customer-interface push is a ciphered `DataNotification` with no association — a
listener, not a session:

```rust,no_run
use dlms_cosem_kit::client::{NotificationListener, SingleMeterKeys};
use dlms_cosem_kit::security::{KeyRing, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle};

let mut listener = NotificationListener::new(
    RustCryptoProvider::new(KeyRing::default()),
    SingleMeterKeys::new(SystemTitle::new(*b"LGZ\x00\x12\x34\x56\x78"), KeyRing::new([0x00; 16], [0xD0; 16])),
    // What the listener requires — never what the frame claims.
    SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
);
let frame: &[u8] = &[];               // whatever arrived on the M-Bus or P1 port
let mut scratch = [0u8; 512];
if let Ok(push) = listener.handle(frame, &mut scratch) {
    println!("{:?}", push.body);
}
```

## Features

`default = ["std", "client", "server", "hdlc", "wrapper", "p1", "suite0", "obis-names"]`

| Feature | What it switches on |
|---|---|
| `client` / `server` | The two engines. With `std`, `client` adds the blocking `Client` and its transports. |
| `hdlc` / `wrapper` / `p1` | The HDLC data link, the TCP/UDP wrapper, the P1 customer interface. |
| `sn` | Short-name referencing, for pre-logical-name meters. Off by default. |
| `suite0` | The AES-GCM provider: ciphering under suites 0, 1 and 2. Implies `crypto`. |
| `crypto` | Zeroised key storage and constant-time comparison, without a cipher. |
| `obis-names` | Names for the well-known OBIS codes. |
| `std` / `alloc` / `heapless` | Environment. `std` implies `alloc` and brings `OsRandom`. |

Every flag gates code that exists, and CI builds each one alone.

## Status

Pre-1.0: the minor version is the breaking one.

- **Built:** every APDU; GET/SET/ACTION/ACCESS with every list form; short-name
  referencing; push both ways; block transfer and general block transfer in both
  directions, chosen by both engines; suites 0–2 symmetric protection with key wrap and
  dedicated keys; HLS-GMAC; replay rejection; HDLC, the wrapper, P1; the blocking driver.
- **Refused by name, not guessed:** HLS mechanisms 3, 4, 6, 7; the asymmetric halves of
  suites 1 and 2 (`general-signing`, agreed and wrapped keys).
- **Not built:** CoAP, SMS, M-Bus, mode E, gateway routing, push scheduling, async drivers.
- **Persist the invocation counter.** Restarting from an old value under an unchanged key
  repeats GCM nonces. Both engines and the driver expose the value to store.
- **Interoperability is untested.** Almost every test is this crate agreeing with itself;
  the independent evidence is the NIST/RFC vectors and published encodings. It is
  "verified against the standard's vectors", not "conformant".

The [status page](https://hupe1980.github.io/dlms-cosem-kit/docs/status/) has the detail.

## Standards

Blue Book Ed 18 and Green Book Ed 12 (DLMS UA) are the masters; IEC 62056-5-3, -6-1 and
-6-2 mirror them. They are copyrighted and not redistributed: this crate contains
encodings, tags, class ids and OBIS codes — facts — and no specification prose.

## Examples

```sh
cargo run --example association   # a whole ciphered association, no sockets
cargo run --example decode        # hex in, a decoded APDU out
cargo run --example p1            # a DSMR telegram
cargo run --example meter         # a meter simulator on 127.0.0.1:4059 (any DLMS client can read it)
cargo run --example read          # read it — or a real meter: `-- 10.0.0.5:4059`
```

Add `-- --ciphered` to both `meter` and `read` for the HLS-GMAC, authenticated-encrypted pair.

## Documentation

- **[Guides and reference](https://hupe1980.github.io/dlms-cosem-kit/)** — getting started,
  the cookbook, the security model, the transports, hosting a meter, and building for a
  microcontroller.
- **[API documentation](https://docs.rs/dlms-cosem-kit)** — generated from the same source.
- **[CHANGELOG.md](CHANGELOG.md)** — what changed, and when.

## License

MIT OR Apache-2.0, at your option.
