//! General block transfer, chosen by the engines themselves.
//!
//! Every test here is the client session against the server with no I/O in between: an
//! APDU out of one goes into the other. That is self-agreement — both ends share this
//! crate's reading of the GBT fields, which is labelled derived in `xdlms::gbt` — so these
//! tests pin behaviour and bounds, not conformance. No third-party GBT bytes exist yet.

mod support;

use std::collections::VecDeque;

use dlms_cosem_kit::acse::AuthMechanism;
use dlms_cosem_kit::axdr::Data;
use dlms_cosem_kit::client::{AccessItem, AssociationStep, ClientConfig, ClientSession, Response};
use dlms_cosem_kit::codec::ErrorKind;
use dlms_cosem_kit::security::{
    FixedRandom, KeyRing, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle,
};
use dlms_cosem_kit::server::{Server, ServerConfig};
use dlms_cosem_kit::xdlms::{AttributeDescriptor, Conformance, DataAccessResult, GbtSender, ServiceError};
use support::{ENERGY, IMAGE, LOAD_PROFILE, PROFILE_ROWS, TestMeter};

const GUEK: [u8; 16] = [0x00; 16];
const GAK: [u8; 16] = [0xD0; 16];
const CLIENT_TITLE: SystemTitle = SystemTitle::new(*b"CLI\x00\x00\x00\x00\x01");
const SERVER_TITLE: SystemTitle = SystemTitle::new(*b"MMM\x00\x00\xBC\x61\x4E");
const GBT_TAG: u8 = 0xE0;

type Client = ClientSession<RustCryptoProvider<FixedRandom>, 4096>;
type Meter<const N: usize> = Server<TestMeter, RustCryptoProvider<FixedRandom>, N>;

fn provider(ring: KeyRing, seed: u8) -> RustCryptoProvider<FixedRandom> {
    RustCryptoProvider::with_rng(ring, FixedRandom(seed))
}

fn plain_pair<const N: usize>(client: ClientConfig, server: ServerConfig) -> (Client, Meter<N>) {
    (
        ClientSession::new(client, provider(KeyRing::default(), 0xA1)),
        Server::new(server, TestMeter::default(), provider(KeyRing::default(), 0xB2)),
    )
}

fn ciphered_pair<const N: usize>(max_pdu: u16) -> (Client, Meter<N>) {
    let policy = SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0);
    (
        ClientSession::new(
            ClientConfig {
                system_title: Some(CLIENT_TITLE),
                mechanism: AuthMechanism::HighGmac,
                security: policy,
                max_pdu_size: max_pdu,
                ..Default::default()
            },
            provider(KeyRing::new(GUEK, GAK), 0xA1),
        ),
        Server::new(
            ServerConfig {
                system_title: Some(SERVER_TITLE),
                mechanism: AuthMechanism::HighGmac,
                security: policy,
                ..Default::default()
            },
            TestMeter::default(),
            provider(KeyRing::new(GUEK, GAK), 0xB2),
        ),
    )
}

fn associate<const N: usize>(client: &mut Client, server: &mut Meter<N>) {
    let mut c = [0u8; 1024];
    let mut s = [0u8; 1024];
    let n = client.associate_request(&mut c).unwrap();
    let m = server.handle(&c[..n], &mut s).unwrap();
    let mut step = client.handle_associate_response(&s[..m]).unwrap();
    if step == AssociationStep::HlsReplyRequired {
        let n = client.hls_reply_request(&mut c).unwrap();
        let m = server.handle(&c[..n], &mut s).unwrap();
        step = client.handle_hls_reply_response(&s[..m]).unwrap();
    }
    assert_eq!(step, AssociationStep::Established);
}

/// What one exchange cost and carried.
#[derive(Debug, Default)]
struct Wire {
    /// Every APDU the server emitted, in order.
    from_server: Vec<Vec<u8>>,
    /// How many acknowledgements the client sent.
    acks: usize,
}

/// Send `request`, deliver every server APDU (pulling streamed blocks with `poll_block`),
/// answer acknowledgements, and hand the final response to `check`.
///
/// `tamper` sees each server APDU before the client does and may drop it (`None`) or
/// change it.
fn exchange<const N: usize, T>(
    client: &mut Client,
    server: &mut Meter<N>,
    request: &[u8],
    buf: &mut [u8],
    mut tamper: impl FnMut(Vec<u8>) -> Option<Vec<u8>>,
    check: impl FnOnce(Response<'_>) -> T,
) -> (T, Wire) {
    let mut wire = Wire::default();
    let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut to_server = Some(request.to_vec());
    for _ in 0..10_000 {
        if let Some(req) = to_server.take() {
            let mut s = vec![0u8; 4096];
            let m = server.handle(&req, &mut s).unwrap();
            if m > 0 {
                queue.push_back(s[..m].to_vec());
            }
            while let Some(m) = server.poll_block(&mut s).unwrap() {
                queue.push_back(s[..m].to_vec());
            }
        }
        let apdu = queue.pop_front().expect("the client is waiting and nothing is coming: a deadlock");
        wire.from_server.push(apdu.clone());
        let Some(apdu) = tamper(apdu) else { continue };
        match client.handle_response(&apdu, buf).unwrap() {
            Response::Pending => {}
            Response::Acknowledge(ack) => {
                wire.acks += 1;
                to_server = Some(ack.as_bytes().to_vec());
            }
            other => return (check(other), wire),
        }
    }
    panic!("the exchange did not converge");
}

fn block_number(apdu: &[u8]) -> Option<u16> {
    (apdu.first() == Some(&GBT_TAG)).then(|| u16::from_be_bytes([apdu[2], apdu[3]]))
}

fn rows(r: Response<'_>) -> usize {
    match r {
        Response::Data(d) => d.as_array().expect("an array").len(),
        other => panic!("expected the profile, got {other:?}"),
    }
}

/// US2-1: with GBT negotiated, a reply too large for the client goes out as GBT blocks
/// rather than service-level datablocks.
#[test]
fn a_large_read_is_answered_with_gbt_when_negotiated() {
    let (mut client, mut server) =
        plain_pair::<4096>(ClientConfig { max_pdu_size: 256, ..Default::default() }, ServerConfig::default());
    associate(&mut client, &mut server);
    let mut req = [0u8; 256];
    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut req).unwrap();
    let mut buf = [0u8; 4096];
    let (got, wire) = exchange(&mut client, &mut server, &req[..n], &mut buf, Some, rows);
    assert_eq!(got, PROFILE_ROWS);
    assert!(wire.from_server.iter().all(|a| a[0] == GBT_TAG), "every APDU is a GBT block");
    assert!(wire.from_server.iter().all(|a| a.len() <= 256), "and each fits the client");
    assert!(!client.is_receiving_blocks());
}

/// US2-4 / US2-5: without GBT the service-level forms are used, and without either the
/// read is refused by name.
#[test]
fn without_gbt_the_service_blocks_are_used_and_without_either_the_read_is_refused() {
    let no_gbt = Conformance::CLIENT_DEFAULT.difference(Conformance::GENERAL_BLOCK_TRANSFER);
    let (mut client, mut server) = plain_pair::<4096>(
        ClientConfig { max_pdu_size: 256, conformance: no_gbt, ..Default::default() },
        ServerConfig::default(),
    );
    associate(&mut client, &mut server);
    let mut req = [0u8; 256];
    let mut s = [0u8; 4096];
    let mut buf = [0u8; 4096];
    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut req).unwrap();
    let m = server.handle(&req[..n], &mut s).unwrap();
    assert!(matches!(client.handle_response(&s[..m], &mut buf).unwrap(), Response::Block { number: 1, .. }));

    let neither = no_gbt.difference(Conformance::BLOCK_TRANSFER_WITH_GET_OR_READ);
    let (mut client, mut server) = plain_pair::<4096>(
        ClientConfig { max_pdu_size: 256, conformance: neither, ..Default::default() },
        ServerConfig::default(),
    );
    associate(&mut client, &mut server);
    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut req).unwrap();
    let m = server.handle(&req[..n], &mut s).unwrap();
    assert_eq!(
        client.handle_response(&s[..m], &mut buf).unwrap(),
        Response::DataError(DataAccessResult::DataBlockUnavailable)
    );
}

/// SC-002: an 8 KiB value at window 4 costs at most ⌈blocks / 4⌉ acknowledgements.
#[test]
fn a_window_of_four_costs_a_quarter_of_the_acknowledgements() {
    let (mut client, mut server) = plain_pair::<9000>(
        ClientConfig { max_pdu_size: 512, gbt_window: 4, ..Default::default() },
        ServerConfig { gbt_window: 4, ..Default::default() },
    );
    server.store_mut().image = (0..8192u32).map(|i| (i % 251) as u8).collect();
    associate(&mut client, &mut server);
    let mut req = [0u8; 256];
    let n = client.get_request(AttributeDescriptor::new(18, IMAGE, 2), None, &mut req).unwrap();
    let mut buf = vec![0u8; 9000];
    let (len, wire) = exchange(&mut client, &mut server, &req[..n], &mut buf, Some, |r| match r {
        Response::Data(Data::OctetString(b)) => b.len(),
        other => panic!("{other:?}"),
    });
    assert_eq!(len, 8192);
    let blocks = wire.from_server.len();
    // The first window is one block (the client has said nothing yet), every later one
    // four; the last block of the transfer is not acknowledged.
    assert!(blocks >= 17, "8 KiB over ~500-byte blocks");
    assert!(wire.acks <= blocks.div_ceil(4), "{} acks for {blocks} blocks", wire.acks);
}

/// 001-large-transfers-driver/SR-002: a client announcing 63 gets at most the server's
/// configured window per acknowledgement.
#[test]
fn a_client_window_is_clamped_to_the_servers() {
    let (mut client, mut server) = plain_pair::<4096>(
        ClientConfig { max_pdu_size: 128, gbt_window: 63, ..Default::default() },
        ServerConfig { gbt_window: 3, ..Default::default() },
    );
    associate(&mut client, &mut server);
    let mut req = [0u8; 256];
    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut req).unwrap();
    // Drive by hand and count the blocks each acknowledgement releases.
    let mut s = [0u8; 4096];
    let mut buf = [0u8; 4096];
    let mut next = req[..n].to_vec();
    let mut burst_max = 0;
    'outer: loop {
        let mut burst = Vec::new();
        let m = server.handle(&next, &mut s).unwrap();
        if m > 0 {
            burst.push(s[..m].to_vec());
        }
        while let Some(m) = server.poll_block(&mut s).unwrap() {
            burst.push(s[..m].to_vec());
        }
        burst_max = burst_max.max(burst.len());
        for apdu in burst {
            match client.handle_response(&apdu, &mut buf).unwrap() {
                Response::Pending => {}
                Response::Acknowledge(ack) => {
                    next = ack.as_bytes().to_vec();
                    continue 'outer;
                }
                Response::Data(_) => break 'outer,
                other => panic!("{other:?}"),
            }
        }
    }
    assert_eq!(burst_max, 3, "63 announced, 3 configured");
}

/// 001-large-transfers-driver/SR-003, SC-003: a block lost in the middle of a window is
/// resent after the client acknowledges the last one it got in order, and the value is
/// byte-identical.
#[test]
fn a_dropped_block_is_retried_and_the_value_is_identical() {
    let config = || {
        (
            ClientConfig { max_pdu_size: 128, gbt_window: 4, ..Default::default() },
            ServerConfig { gbt_window: 4, ..Default::default() },
        )
    };
    let (c, s) = config();
    let (mut client, mut server) = plain_pair::<4096>(c, s);
    associate(&mut client, &mut server);
    let mut req = [0u8; 256];
    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut req).unwrap();
    let mut buf = [0u8; 4096];
    let mut dropped = false;
    let (clean, _) = {
        let (c, s) = config();
        let (mut c2, mut s2) = plain_pair::<4096>(c, s);
        associate(&mut c2, &mut s2);
        let mut r = [0u8; 256];
        let k = c2.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut r).unwrap();
        let mut b = [0u8; 4096];
        exchange(&mut c2, &mut s2, &r[..k], &mut b, Some, |r| match r {
            Response::Data(d) => format!("{d:?}"),
            o => panic!("{o:?}"),
        })
    };
    let (got, wire) = exchange(
        &mut client,
        &mut server,
        &req[..n],
        &mut buf,
        |a| {
            if block_number(&a) == Some(3) && !dropped {
                dropped = true;
                return None;
            }
            Some(a)
        },
        |r| match r {
            Response::Data(d) => format!("{d:?}"),
            o => panic!("{o:?}"),
        },
    );
    assert!(dropped);
    assert_eq!(got, clean, "byte-identical after the retry");
    let threes = wire.from_server.iter().filter(|a| block_number(a) == Some(3)).count();
    assert_eq!(threes, 2, "block 3 was sent exactly twice");
}

/// 001-large-transfers-driver/SR-004: in a ciphered association the protected reply
/// crosses in blocks and verifies once, on the whole; a flipped byte in any block fails
/// the tag after reassembly.
#[test]
fn a_ciphered_reply_verifies_on_the_whole_and_a_flipped_byte_fails_it() {
    let (mut client, mut server) = ciphered_pair::<4096>(128);
    associate(&mut client, &mut server);
    let mut req = [0u8; 512];
    let mut buf = [0u8; 4096];
    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut req).unwrap();
    let (got, _) = exchange(&mut client, &mut server, &req[..n], &mut buf, Some, rows);
    assert_eq!(got, PROFILE_ROWS);

    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut req).unwrap();
    let mut s = [0u8; 4096];
    let m = server.handle(&req[..n], &mut s).unwrap();
    let mut blocks = vec![s[..m].to_vec()];
    let mut next;
    let failure = loop {
        let mut apdu = blocks.remove(0);
        if block_number(&apdu) == Some(2) {
            let at = apdu.len() - 1;
            apdu[at] ^= 0x01;
        }
        match client.handle_response(&apdu, &mut buf) {
            Ok(Response::Pending) => {}
            Ok(Response::Acknowledge(ack)) => {
                next = ack.as_bytes().to_vec();
                let m = server.handle(&next, &mut s).unwrap();
                blocks.push(s[..m].to_vec());
                while let Some(m) = server.poll_block(&mut s).unwrap() {
                    blocks.push(s[..m].to_vec());
                }
            }
            Ok(other) => panic!("a tampered reply was accepted: {other:?}"),
            Err(e) => break e,
        }
    };
    assert!(matches!(failure.kind, ErrorKind::BadTag), "{failure:?}");
}

/// 001-large-transfers-driver/SR-004: a plaintext response smuggled inside GBT blocks into a
/// ciphered association is refused as the downgrade it is.
#[test]
fn a_plaintext_reply_inside_gbt_is_refused_in_a_ciphered_association() {
    let (mut client, mut server) = ciphered_pair::<4096>(128);
    associate(&mut client, &mut server);
    let mut req = [0u8; 512];
    client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut req).unwrap();
    // get-response-normal, invoke id 0xC1, data: an octet string of 300 bytes.
    let mut plain = vec![0xC4, 0x01, 0xC1, 0x00, 0x09, 0x82, 0x01, 0x2C];
    plain.extend(std::iter::repeat_n(0x55, 300));
    let mut sender = GbtSender::new(&plain, 100, 1, false).unwrap();
    let mut buf = [0u8; 4096];
    let mut frame = [0u8; 256];
    let result = loop {
        let n = sender.next_block(&mut frame[1..]).unwrap().unwrap();
        frame[0] = GBT_TAG;
        match client.handle_response(&frame[..=n], &mut buf) {
            Ok(Response::Acknowledge(_)) => sender.acknowledge(sender.block()).unwrap(),
            other => break other,
        }
    };
    assert_eq!(result.unwrap_err().kind, ErrorKind::UnexpectedMessage);
}

/// Send `request` to the server as GBT blocks of `fragment` bytes, answering its
/// acknowledgements, and return its final reply.
fn send_as_gbt<const N: usize>(server: &mut Meter<N>, request: &[u8], fragment: usize) -> Vec<u8> {
    let mut sender = GbtSender::new(request, fragment, 1, false).unwrap();
    let mut frame = vec![0u8; fragment + 16];
    let mut s = [0u8; 4096];
    loop {
        let n = sender.next_block(&mut frame[1..]).unwrap().expect("a block to send");
        frame[0] = GBT_TAG;
        let m = server.handle(&frame[..=n], &mut s).unwrap();
        let reply = s[..m].to_vec();
        let is_ack = reply.first() == Some(&GBT_TAG) && reply.len() == 7;
        if !is_ack {
            return reply;
        }
        sender.acknowledge(u16::from_be_bytes([reply[4], reply[5]])).unwrap();
    }
}

/// US2-6: a long request arriving as GBT is applied as if it had come in one APDU.
#[test]
fn a_long_set_arriving_as_gbt_is_applied() {
    let (mut client, mut server) =
        plain_pair::<4096>(ClientConfig::default(), ServerConfig { max_pdu_size: 256, ..Default::default() });
    associate(&mut client, &mut server);
    let image = vec![0x5Au8; 600];
    let mut req = [0u8; 1024];
    let n = client
        .set_request(AttributeDescriptor::new(18, IMAGE, 2), None, Data::OctetString(&image), &mut req)
        .unwrap();
    let reply = send_as_gbt(&mut server, &req[..n], 200);
    let mut buf = [0u8; 1024];
    assert_eq!(client.handle_response(&reply, &mut buf).unwrap(), Response::Ok);
    assert_eq!(server.store().image, image);
}

/// 001-large-transfers-driver/SR-005: a SET that arrives in blocks passes the same access
/// check as one that does not.
#[test]
fn a_set_over_gbt_without_write_access_is_denied() {
    let (mut client, mut server) =
        plain_pair::<4096>(ClientConfig::default(), ServerConfig { max_pdu_size: 256, ..Default::default() });
    associate(&mut client, &mut server);
    let before = server.store().energy_wh;
    let big = vec![0u8; 600];
    let mut req = [0u8; 1024];
    let n = client
        .set_request(AttributeDescriptor::new(3, ENERGY, 2), None, Data::OctetString(&big), &mut req)
        .unwrap();
    let reply = send_as_gbt(&mut server, &req[..n], 200);
    let mut buf = [0u8; 1024];
    assert_eq!(
        client.handle_response(&reply, &mut buf).unwrap(),
        Response::DataError(DataAccessResult::ReadWriteDenied)
    );
    assert_eq!(server.store().energy_wh, before, "the store was not written");
}

/// 001-large-transfers-driver/SR-001: a GBT request larger than the server's buffer is
/// refused by name, and the server answers the next request normally.
#[test]
fn an_oversize_gbt_request_is_refused_and_the_server_stays_usable() {
    let (mut client, mut server) =
        plain_pair::<1024>(ClientConfig::default(), ServerConfig { max_pdu_size: 256, ..Default::default() });
    associate(&mut client, &mut server);
    let big = vec![0u8; 2000];
    let mut req = vec![0u8; 4096];
    // The session's own scratch is 4096, so it can build what the server cannot hold.
    let n = client
        .set_request(AttributeDescriptor::new(18, IMAGE, 2), None, Data::OctetString(&big), &mut req)
        .unwrap();
    let reply = send_as_gbt(&mut server, &req[..n], 200);
    let mut buf = [0u8; 1024];
    match client.handle_response(&reply, &mut buf).unwrap() {
        Response::Exception(e) => assert_eq!(e.service_error, ServiceError::PduTooLong),
        other => panic!("expected pdu-too-long, got {other:?}"),
    }
    let n = client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut req).unwrap();
    let mut s = [0u8; 1024];
    let m = server.handle(&req[..n], &mut s).unwrap();
    assert!(matches!(client.handle_response(&s[..m], &mut buf).unwrap(), Response::Data(_)));
}

/// 001-large-transfers-driver/SR-001: a client whose buffer is smaller than the reply
/// refuses it rather than growing anything.
#[test]
fn a_client_buffer_smaller_than_the_reply_refuses_it() {
    let (mut client, mut server) =
        plain_pair::<4096>(ClientConfig { max_pdu_size: 256, ..Default::default() }, ServerConfig::default());
    associate(&mut client, &mut server);
    let mut req = [0u8; 256];
    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut req).unwrap();
    let mut s = [0u8; 4096];
    let mut small = [0u8; 512];
    let mut next = req[..n].to_vec();
    let err = 'outer: loop {
        let m = server.handle(&next, &mut s).unwrap();
        let mut burst = vec![s[..m].to_vec()];
        while let Some(m) = server.poll_block(&mut s).unwrap() {
            burst.push(s[..m].to_vec());
        }
        for apdu in burst {
            match client.handle_response(&apdu, &mut small) {
                Ok(Response::Pending) => {}
                Ok(Response::Acknowledge(ack)) => {
                    next = ack.as_bytes().to_vec();
                    continue 'outer;
                }
                Ok(other) => panic!("{other:?}"),
                Err(e) => break 'outer e,
            }
        }
    };
    assert!(matches!(err.kind, ErrorKind::BufferTooSmall { .. }));
    assert!(!client.is_receiving_blocks(), "the transfer is abandoned");
}

/// 001-large-transfers-driver/SR-003: blocks answering an earlier request are not taken as
/// the answer to the current one.
#[test]
fn blocks_for_an_abandoned_request_are_not_the_answer_to_the_next() {
    let (mut client, mut server) = plain_pair::<4096>(
        ClientConfig { max_pdu_size: 256, gbt_window: 63, ..Default::default() },
        ServerConfig { gbt_window: 63, ..Default::default() },
    );
    associate(&mut client, &mut server);
    let mut req = [0u8; 256];
    let n = client.get_request(AttributeDescriptor::new(7, LOAD_PROFILE, 2), None, &mut req).unwrap();
    // Collect the first request's whole reply, acknowledging as a client would.
    let mut buf = [0u8; 4096];
    let (_, wire) = exchange(&mut client, &mut server, &req[..n], &mut buf, Some, |_| ());
    // A new request is made (and lost); the old reply is replayed at the client.
    client.get_request(AttributeDescriptor::new(3, ENERGY, 2), None, &mut req).unwrap();
    let mut result = None;
    for apdu in &wire.from_server {
        match client.handle_response(apdu, &mut buf) {
            Ok(Response::Pending | Response::Acknowledge(_)) => {}
            other => {
                result = Some(other.map(|r| format!("{r:?}")));
                break;
            }
        }
    }
    assert_eq!(result.unwrap().unwrap_err().kind, ErrorKind::UnexpectedMessage);
}

/// ACCESS has no block form of its own; GBT carries it like any other reply.
#[test]
fn an_access_reply_too_large_for_one_apdu_crosses_as_gbt() {
    let (mut client, mut server) =
        plain_pair::<4096>(ClientConfig { max_pdu_size: 256, ..Default::default() }, ServerConfig::default());
    associate(&mut client, &mut server);
    let mut req = [0u8; 256];
    let n = client
        .access_request(
            &[AccessItem::Get { descriptor: AttributeDescriptor::new(7, LOAD_PROFILE, 2), access: None }],
            &mut req,
        )
        .unwrap();
    let mut buf = [0u8; 4096];
    let (count, wire) = exchange(&mut client, &mut server, &req[..n], &mut buf, Some, |r| match r {
        Response::Access { data, .. } => data.iter().next().unwrap().unwrap().as_array().unwrap().len(),
        o => panic!("{o:?}"),
    });
    assert_eq!(count, PROFILE_ROWS);
    assert!(wire.from_server.len() > 1);
}
