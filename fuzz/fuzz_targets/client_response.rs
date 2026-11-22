#![no_main]
//! The client's response path, driven by a hostile meter.
//!
//! The session is associated first — against this crate's own server, so the fuzzer
//! spends its time past the handshake — and then sees message after message from the
//! attacker: general-block-transfer blocks in any order, acknowledgements of nothing,
//! responses to requests never made. It must answer or refuse each without aborting, and
//! a GBT reassembly may never grow past the one buffer it was given.

use dlms_cosem_kit::client::{AssociationStep, ClientConfig, ClientSession};
use dlms_cosem_kit::security::{FixedRandom, KeyRing, RustCryptoProvider};
use dlms_cosem_kit::server::{ObjectStore, Server, ServerConfig, StoreResult};
use dlms_cosem_kit::xdlms::{AttributeDescriptor, DataAccessResult, SelectiveAccess};
use dlms_cosem_kit::{codec::Writer, cosem::AttributeAccess, cosem::MethodAccess, obis::Obis};
use libfuzzer_sys::fuzz_target;

struct Empty;

impl ObjectStore for Empty {
    fn get_attribute(&self, _: u16, _: Obis, _: i8, _: Option<SelectiveAccess<'_>>, _: &mut dyn Writer) -> StoreResult<()> {
        Err(DataAccessResult::ObjectUndefined)
    }
    fn attribute_access(&self, _: u16, _: Obis, _: i8) -> AttributeAccess {
        AttributeAccess::READ
    }
    fn method_access(&self, _: u16, _: Obis, _: i8) -> MethodAccess {
        MethodAccess::empty()
    }
}

fuzz_target!(|bytes: &[u8]| {
    let mut client: ClientSession<RustCryptoProvider<FixedRandom>> =
        ClientSession::new(ClientConfig::default(), RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(1)));
    let mut server: Server<Empty, RustCryptoProvider<FixedRandom>> =
        Server::new(ServerConfig::default(), Empty, RustCryptoProvider::with_rng(KeyRing::default(), FixedRandom(2)));
    let mut a = [0u8; 1024];
    let mut b = [0u8; 1024];
    let Ok(n) = client.associate_request(&mut a) else { return };
    let Ok(m) = server.handle(&a[..n], &mut b) else { return };
    if client.handle_associate_response(&b[..m]) != Ok(AssociationStep::Established) {
        return;
    }
    // One outstanding request, so invoke-id binding is exercised as well.
    let _ = client.get_request(AttributeDescriptor::new(3, Obis::new(1, 0, 1, 8, 0, 255), 2), None, &mut a);
    // The same buffer for every message, as a GBT transfer requires — and small, so the
    // capacity bound is reached.
    let mut buf = [0u8; 512];
    for message in bytes.split(|b| *b == 0xFE) {
        if !message.is_empty() {
            let _ = client.handle_response(message, &mut buf);
        }
    }
});
