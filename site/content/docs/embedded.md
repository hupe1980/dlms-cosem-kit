+++
title = "Embedded and no_std"
description = "Build dlms-cosem-kit for a Cortex-M or RISC-V microcontroller with no allocator, and check the panic-freedom claim yourself in one command."
weight = 60
+++

## Building without a standard library

```toml
[dependencies]
dlms-cosem-kit = { version = "0.3", default-features = false, features = [
    "client", "hdlc", "suite0",
] }
```

This configuration enables the client, HDLC and suite-0 protection without an allocator.
Add `server`, `wrapper` or `p1` for those components.

`alloc` adds the owned `DataBuf` tree, `Vec` as an output sink, and expanding a compact
array into owned rows. `heapless` adds `heapless::Vec` as an output sink for a build with
no allocator at all.

`thumbv7em-none-eabihf`, `riscv32imac-unknown-none-elf` and `wasm32-unknown-unknown` are
built in CI, with and without `alloc`.

## Where the memory goes

The server has a const-generic buffer size:

```rust,ignore
let server: Server<MyStore, MyProvider, 4096> = Server::new(config, store, provider);
```

That `N` and the negotiated PDU size are **different limits**, and confusing them is the
usual mistake:

- `max_pdu_size` bounds one *message*. A value larger than it is delivered over block
  transfer, however many blocks that takes.
- `N` bounds the whole *value*, because a response is built before it is cut up. A meter
  whose load profile encodes to eight kilobytes needs `N` of at least that, whatever PDU
  size it negotiates.

A store that overruns `N` gets a write error from its output sink and reports whatever
result it chooses. Nothing is truncated silently.

The sans-I/O engines use caller-provided reassembly buffers. Budget stack space for
multiple `N`-sized buffers during `Server::handle` and measure on your target.

## No panic reachable from the network

Everything in the crate faces the network before any key has been checked, so the ways a
decoder can abort the process are denied outright:

- `#![forbid(unsafe_code)]` — there is no `unsafe` anywhere in the crate;
- `panic!`, `unwrap`, `expect`, `todo` and `unimplemented` are denied in the library;
- every decoder returns a `Result` carrying the **byte offset** the failure happened at.

Lints are an argument, though. The claim is *measured*:

```sh
CARGO_PROFILE_RELEASE_LTO=false cargo build --release \
  --target thumbv7em-none-eabihf --no-default-features \
  --features client,server,hdlc,wrapper,p1,suite0

nm target/thumbv7em-none-eabihf/release/libdlms_cosem_kit.rlib \
  | grep -E 'core[0-9]+panicking|panic_fmt'
```

That prints nothing, and CI fails if it ever does.

Disable LTO for this check so the archive contains machine code.

## Randomness and time

**Randomness is injected.** A provider without an entropy source refuses to produce a high
level security challenge rather than returning something predictable:

```rust,ignore
impl RandomSource for MyHardwareRng {
    fn fill(&self, out: &mut [u8]) -> Result<()> { /* … */ }
}

let provider = RustCryptoProvider::with_rng(KeyRing::new(guek, gak), MyHardwareRng);
```

The core receives timestamps as data. Your transport supplies timers and deadlines.

## Keys on a device

The default provider keeps keys in zeroised memory. Implement `CryptoProvider` to use
a secure element. Persist the invocation counter across restarts when reusing keys.
See the [security guide](@/docs/security.md).
