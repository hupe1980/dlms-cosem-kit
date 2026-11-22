+++
title = "Getting started"
description = "Install dlms-cosem-kit, understand what sans-I/O means for your code, and read your first register from a smart meter over TCP."
weight = 10
+++

## What this crate is, and is not

`dlms-cosem-kit` implements **DLMS/COSEM** — IEC 62056, the protocol nearly every European
smart meter speaks. The DLMS User Association describes the standard in three steps, and
the crate follows the same three:

1. **Modelling.** A meter is a set of *logical devices* holding *objects*. An object is an
   instance of an *interface class* (a `class_id` and a `version`) named by a six-byte
   **OBIS** code like `1-0:1.8.0*255`. Attribute 1 is always that name.
2. **Messaging.** GET, SET, ACTION and ACCESS request and change those attributes;
   DataNotification pushes them unasked. A-XDR encodes the values, BER encodes the
   handshake.
3. **Transporting.** HDLC on an optical probe or RS-485, a thin wrapper over TCP or UDP,
   and — on the customer side — the P1 telegram.

It is a **library, not a stack**. No sockets, no clock, no async runtime, no cryptography
in the core: those belong to you. That is the point rather than an omission — the same
protocol logic drives a head-end under Tokio, a decoder compiled to WASM, and meter
firmware on a Cortex-M with no allocator.

## Install

```toml
[dependencies]
dlms-cosem-kit = "0.1"
```

The default feature set is `std`, `client`, `server`, `hdlc`, `wrapper`, `p1`, `suite0`
and `obis-names`. Take what you need:

| Feature | What it switches on |
|---|---|
| `client` / `server` | The two engines. A head-end needs no server; meter firmware needs no client. |
| `hdlc` / `wrapper` / `p1` | The transports: the HDLC data link, the TCP/UDP wrapper, the P1 customer interface. |
| `suite0` | The AES-GCM provider, which serves ciphering under suites 0, 1 and 2. Implies `crypto`. |
| `crypto` | Zeroised key storage and constant-time comparison, without a cipher. |
| `obis-names` | Names for the well-known OBIS codes. Pure tables; off saves the strings. |
| `std` / `alloc` / `heapless` | Environment. `std` implies `alloc`. |

**Every feature switches code that exists**, and CI builds each one on its own. A flag
that gates nothing is worse than no flag: it tells you the crate does something it does
not, and it makes `--all-features` a weaker check than it looks.

## Read a meter

With `std`, [`Client`](https://docs.rs/dlms-cosem-kit/latest/dlms_cosem_kit/client/struct.Client.html)
is a blocking driver over a transport. It runs the association — every pass of high level
security included — and does block transfer and general block transfer inside each call,
in both directions:

```rust,ignore
use dlms_cosem_kit::client::{Client, ClientConfig};
use dlms_cosem_kit::obis::names::ACTIVE_ENERGY_IMPORT_TOTAL;
use dlms_cosem_kit::security::{KeyRing, RustCryptoProvider};
use dlms_cosem_kit::transport::WrapperTransport;
use dlms_cosem_kit::xdlms::AttributeDescriptor;

let link = WrapperTransport::connect("10.0.0.5:4059", 0x10, 0x01)?;   // public client → management LD
let mut meter: Client<_, _> =
    Client::connect(link, ClientConfig::default(), RustCryptoProvider::os(KeyRing::default()))?;

println!("{}", meter.read_scaled(3, ACTIVE_ENERGY_IMPORT_TOTAL)?);      // 12345678 Wh
let profile = meter.get(AttributeDescriptor::new(7, LOAD_PROFILE, 2))?; // however many blocks
meter.release()?;
```

`read_scaled(3, …)` reads attributes 2 and 3 of a *Register* (class 3) in one round trip —
the value and its `scaler_unit` — and keeps them as an exact integer and an exponent
rather than a float, because 12 345 with a scaler of −3 is exactly 12.345 kWh and
`12.345_f64` is not. Every failure is one `ClientError` that names what the meter said: a
rejected association with its diagnostic, a refused attribute with its
`DataAccessResult`, a stale invocation counter with the value to move to.

`HdlcTransport` is the other shipped transport — an optical probe, an RS-485 bus or HDLC
over TCP — and anything else is a two-method `Transport` trait.

## What sans-I/O means underneath

The driver is a convenience. Underneath it, the session has no `connect`: it *builds* an
APDU into a buffer you own and *consumes* one out of a buffer you own:

```rust,ignore
let n = session.associate_request(&mut request)?;      // bytes out
session.handle_associate_response(&reply)?;            // bytes in
```

That is the layer for firmware, for an async runtime, and for tests: moving the bytes is
yours — a serial port, an `embedded-io` device, a `Vec`. Two consequences are worth
knowing up front.

**Buffers are parameters, not fields.** `handle_response(apdu, buf)` takes the scratch
buffer to decrypt into, and the value it returns borrows that buffer. A buffer hidden
inside the session would make the borrow checker refuse a caller that wants to hold a
value across the next request, and would hide how long a decrypted plaintext lingers in
memory. Making it a parameter puts both facts in the signature. A response arriving as
general block transfer is gathered into that same buffer, so pass the same one for every
block of it.

**Randomness is injected; time is data.** A provider without an entropy source refuses to
produce a high-level-security challenge rather than returning something predictable;
`RustCryptoProvider::os` uses the operating system's. There is no clock at all — a
timestamp is a `DateTime` you supply, and nothing in the crate can say “wake me in three
seconds”. (The shipped transports set a socket timeout; that is the operating system's
clock, not the crate's.)

## Run something first

Five examples ship with the source, and all of them run:

```sh
cargo run --example association   # a whole ciphered association, no sockets at all
cargo run --example decode        # hex in, a decoded APDU out — a protocol translator
cargo run --example p1            # a DSMR telegram from the customer interface
```

`association` is this page's argument made runnable: both engines in one process, four
passes of high level security, a ciphered read, a breaker operation, and a recorded frame
replayed and refused — with the whole transport being one `copy_from_slice`. Reading it
takes five minutes and answers most of what "sans-I/O" means in practice.

The other two are a pair over a real socket:

```sh
cargo run --example meter         # a meter simulator on 127.0.0.1:4059
cargo run --example read          # read it — or a real meter: `-- 10.0.0.5:4059`
```

`meter` speaks the TCP wrapper, so any DLMS client can be pointed at it, not only this
one.

## What to read next

- **[The cookbook](@/docs/cookbook.md)** — the things people actually do, each one a
  compiled example.
- **[Security](@/docs/security.md)** — if the meter needs a password or a key, start here.
  Invocation counters have one rule you must get right and the crate cannot get it for
  you.
- **[Services and segmentation](@/docs/services.md)** — why reading a load profile needs
  two different segmentation mechanisms at once.
- **[Status](@/docs/status.md)** — what is built, what is refused, and what is not proven.
