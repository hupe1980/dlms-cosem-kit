//! Read a meter over TCP: associate, read some registers, pull a load profile, release.
//!
//! ```sh
//! cargo run --example meter                 # in one shell
//! cargo run --example read                  # in another
//!
//! cargo run --example meter -- --ciphered   # or the same pair, protected
//! cargo run --example read  -- --ciphered
//!
//! cargo run --example read -- 10.0.0.5:4059 # or a real meter
//! ```
//!
//! `Client` is the blocking driver over the sans-I/O `ClientSession` that
//! `examples/association.rs` runs with no sockets at all. Association — high-level
//! security included — block transfer and general block transfer happen inside it; what
//! is left here is what to read.

use dlms_cosem_kit::acse::AuthMechanism;
use dlms_cosem_kit::client::{Client, ClientConfig, ClientError};
use dlms_cosem_kit::cosem::EntryDescriptor;
use dlms_cosem_kit::obis::Obis;
use dlms_cosem_kit::security::{KeyRing, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle};
use dlms_cosem_kit::transport::WrapperTransport;
use dlms_cosem_kit::transport::wrapper::DEFAULT_PORT;
use dlms_cosem_kit::xdlms::{AttributeDescriptor, MethodDescriptor};

const GUEK: [u8; 16] =
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
const GAK: [u8; 16] =
    [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF];
const CLIENT_TITLE: SystemTitle = SystemTitle::new(*b"CLI\x00\x00\x00\x00\x01");

const ENERGY: Obis = Obis::new(1, 0, 1, 8, 0, 255);
const ENERGY_EXPORT: Obis = Obis::new(1, 0, 2, 8, 0, 255);
const POWER: Obis = Obis::new(1, 0, 1, 7, 0, 255);
const CLOCK: Obis = Obis::new(0, 0, 1, 0, 0, 255);
const BREAKER: Obis = Obis::new(0, 0, 96, 3, 10, 255);
const PROFILE: Obis = Obis::new(1, 0, 99, 1, 0, 255);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let ciphered = args.iter().any(|a| a == "--ciphered");
    let addr =
        args.iter().find(|a| !a.starts_with("--")).cloned().unwrap_or(format!("127.0.0.1:{DEFAULT_PORT}"));

    // The wrapper ports are the service access points: 0x10 is the public client, 0x30
    // management; on the meter's side, 1 is the management logical device.
    let link = WrapperTransport::connect(&addr, 0x10, 0x01)?;
    let config = if ciphered {
        ClientConfig {
            system_title: Some(CLIENT_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0),
            // Restored from where the last run stored it — see the end of this file.
            invocation_counter: 0,
            ..Default::default()
        }
    } else {
        ClientConfig::default()
    };
    let keys = if ciphered { KeyRing::new(GUEK, GAK) } else { KeyRing::default() };

    let mut meter: Client<_, _> = match Client::connect(link, config, RustCryptoProvider::os(keys)) {
        Ok(m) => m,
        // The refusal worth acting on: a stale invocation counter, with the value to use.
        Err(ClientError::Exception(e)) if e.expected_invocation_counter.is_some() => {
            return Err(format!(
                "set ClientConfig::invocation_counter to {:?}",
                e.expected_invocation_counter
            )
            .into());
        }
        Err(e) => return Err(e.into()),
    };
    println!("associated with {addr}\n");

    // Three registers, each with its scaler and unit.
    for (label, name) in
        [("import energy", ENERGY), ("export energy", ENERGY_EXPORT), ("active power", POWER)]
    {
        println!("  {label:<16}{}", meter.read_scaled(3, name)?);
    }

    // The clock and the breaker in one round trip; each item has its own result.
    let both =
        meter.get_list(&[AttributeDescriptor::new(8, CLOCK, 2), AttributeDescriptor::new(70, BREAKER, 2)])?;
    for (label, result) in ["clock", "breaker closed"].iter().zip(&both) {
        match result {
            Ok(value) => println!("  {label:<16}{value}"),
            Err(why) => println!("  {label:<16}refused: {why:?}"),
        }
    }
    println!();

    // The whole load profile — far larger than one APDU, so it arrives in blocks. Narrow
    // it at the meter with selective access when only part of it is wanted.
    let profile = meter.get(AttributeDescriptor::new(7, PROFILE, 2))?;
    let mut params = [0u8; 64];
    let first_two = meter.get_selected(
        AttributeDescriptor::new(7, PROFILE, 2),
        EntryDescriptor::entries(1, 2).to_selective_access(&mut params)?,
    )?;
    println!(
        "  load profile: {} rows; selected at the meter: {}\n",
        profile.as_array().map_or(0, <[_]>::len),
        first_two
    );

    // An ACTION that changes something. Access rights are the meter's to enforce.
    match meter.action(MethodDescriptor::new(70, BREAKER, 1), None) {
        Ok(_) => println!("  breaker opened"),
        Err(e) => println!("  breaker not opened: {e}"),
    }

    // The one rule the crate cannot enforce: store the counter before exiting, or the next
    // run repeats every nonce this one used under the same key.
    let counter = meter.invocation_counter();
    meter.release()?;
    if ciphered {
        println!("\npersist the invocation counter: {counter}");
    }
    Ok(())
}
