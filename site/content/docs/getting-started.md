+++
title = "Getting started"
description = "Install dlms-cosem-kit, understand what sans-I/O means for your code, and read your first register from a smart meter over TCP."
weight = 10
+++

## Install

```toml
[dependencies]
dlms-cosem-kit = "0.3"
```

The default features include the blocking client, server, HDLC, TCP wrapper, P1,
symmetric cryptography and OBIS names. For firmware, see the
[embedded build guide](@/docs/embedded.md).

## Try the simulator

From the repository, run these commands in separate terminals.

```sh
cargo run --example meter
cargo run --example read
```

The simulator listens on `127.0.0.1:4059`. For an available port use
`cargo run --example meter -- 0` and run the reader command it prints.
Add `-- --ciphered` to both default-port commands for authenticated encryption.

## Read a register over TCP

Supply the meter address, wrapper ports and association settings for your installation.
This example uses a public association.

```rust
use dlms_cosem_kit::client::{Client, ClientConfig};
use dlms_cosem_kit::obis::names::ACTIVE_ENERGY_IMPORT_TOTAL;
use dlms_cosem_kit::security::{KeyRing, RustCryptoProvider};
use dlms_cosem_kit::transport::WrapperTransport;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let link = WrapperTransport::connect("127.0.0.1:4059", 0x10, 1)?;
    let mut meter: Client<_, _> =
        Client::connect(link, ClientConfig::default(), RustCryptoProvider::os(KeyRing::default()))?;
    println!("{}", meter.read_scaled(3, ACTIVE_ENERGY_IMPORT_TOTAL)?);
    meter.release()?;
    Ok(())
}
```

`read_scaled` reads the register value and its scaler and unit in one request.
For load profiles, use `get_into` with a caller buffer and an optional clock or
entry selector. The [cookbook](@/docs/cookbook.md) shows how to visit the rows.

## Drive the protocol directly

Use `ClientSession` in firmware or under an async runtime. Send the APDU produced by
each request method, then pass the peer's reply to the matching response handler.
Keep the same response scratch buffer for every GBT block in a transfer.
