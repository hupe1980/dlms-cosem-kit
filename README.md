# dlms-cosem-kit

**DLMS/COSEM (IEC 62056) in one Rust crate: sans-I/O, `no_std`, client *and* server.**

[![crates.io](https://img.shields.io/crates/v/dlms-cosem-kit.svg)](https://crates.io/crates/dlms-cosem-kit)
[![docs.rs](https://img.shields.io/docsrs/dlms-cosem-kit)](https://docs.rs/dlms-cosem-kit)
[![license](https://img.shields.io/crates/l/dlms-cosem-kit.svg)](#license)

**[Documentation and guides →](https://hupe1980.github.io/dlms-cosem-kit/)**

Read meters, host COSEM objects, or receive push notifications. The protocol core works
with caller-provided buffers. The blocking client drives TCP wrapper and HDLC connections.

```toml
[dependencies]
dlms-cosem-kit = "0.3"
```

## Read a profile

Pass an associated client and the capture-column count for the selection. The returned
value borrows `storage`. Use `Some(selector)` to read a clock range or entry range.

```rust
use dlms_cosem_kit::client::{Client, ClientError, Transport};
use dlms_cosem_kit::cosem::ProfileBuffer;
use dlms_cosem_kit::obis::Obis;
use dlms_cosem_kit::security::CryptoProvider;
use dlms_cosem_kit::xdlms::AttributeDescriptor;

fn read_profile<T: Transport, P: CryptoProvider>(
    meter: &mut Client<T, P>,
    name: Obis,
    columns: usize,
    storage: &mut [u8],
) -> Result<(), ClientError> {
    let buffer = AttributeDescriptor::new(7, name, 2);
    let value = meter.get_into(buffer, None, storage)?;
    ProfileBuffer::new(&value)?.for_each_cell(columns, |row, col, cell| {
        println!("{row}/{col} {cell:?}");
        Ok(())
    })?;
    Ok(())
}
```

The client accepts up to 64 KiB of encoded result data by default. Set the client limit
with `with_response_capacity`. A smaller output slice sets the limit for that GET.
`ResponseTooLarge` indicates whether to reconnect. For owned values use `get` or
`get_selected`.

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

## Protocol support

The crate implements A-XDR and BER codecs, ACSE associations, logical-name services,
optional short-name referencing, service blocks and general block transfer. Security
includes symmetric ciphering for suites 0–2, HLS-GMAC and replay protection. Persist
the next invocation counter before reusing a key across restarts.

For embedded or async applications, drive the sans-I/O `ClientSession` or `Server`
with your transport. See the [support matrix](https://hupe1980.github.io/dlms-cosem-kit/docs/status/)
for supported security mechanisms and interoperability limits.

## Run the TCP examples

In separate terminals, start the simulator and read its profile.

```sh
cargo run --example meter
cargo run --example read
```

Add `-- --ciphered` to both commands for HLS-GMAC and authenticated encryption.

[Cookbook](https://hupe1980.github.io/dlms-cosem-kit/docs/cookbook/) ·
[API reference](https://docs.rs/dlms-cosem-kit) ·
[Changelog](https://github.com/hupe1980/dlms-cosem-kit/blob/main/CHANGELOG.md)

## License

MIT OR Apache-2.0, at your option.
