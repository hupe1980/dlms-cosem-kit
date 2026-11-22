//! The blocking `Client` driver, over an in-memory transport and over real sockets.

mod support;

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use dlms_cosem_kit::acse::AuthMechanism;
use dlms_cosem_kit::axdr::{Data, DataBuf, Unit};
use dlms_cosem_kit::client::{Client, ClientConfig, ClientError, Transport};
use dlms_cosem_kit::codec::Encode;
use dlms_cosem_kit::cosem::EntryDescriptor;
use dlms_cosem_kit::security::{
    FixedRandom, KeyRing, RustCryptoProvider, SecurityPolicy, SecuritySuite, SystemTitle,
};
use dlms_cosem_kit::server::{Server, ServerConfig};
use dlms_cosem_kit::transport::hdlc::{
    self, Address, Connection, Event, Found, Framer, Parameters, Reassembler, Role,
};
use dlms_cosem_kit::transport::wrapper::{StreamReassembler, Wpdu};
use dlms_cosem_kit::transport::{HdlcTransport, WrapperTransport};
use dlms_cosem_kit::xdlms::{AttributeDescriptor, Conformance, DataAccessResult, MethodDescriptor};
use support::{BREAKER, CLOCK, ENERGY, IMAGE, LOAD_PROFILE, PROFILE_ROWS, SECRET_LOG, TestMeter};

const GUEK: [u8; 16] =
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
const GAK: [u8; 16] =
    [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF];
const CLIENT_TITLE: SystemTitle = SystemTitle::new(*b"CLI\x00\x00\x00\x00\x01");
const SERVER_TITLE: SystemTitle = SystemTitle::new(*b"MMM\x00\x00\xBC\x61\x4E");

type Provider = RustCryptoProvider<FixedRandom>;
type Meter = Server<TestMeter, Provider, 8192>;

/// A transport that is a server, in the same process: every APDU sent is handled at once,
/// and everything the server emits — streamed GBT blocks included — queues for `recv`.
struct InMemory {
    server: Meter,
    queue: VecDeque<Vec<u8>>,
}

impl Transport for InMemory {
    fn send(&mut self, apdu: &[u8]) -> io::Result<()> {
        let mut out = vec![0u8; 8192];
        let n = self.server.handle(apdu, &mut out).map_err(io::Error::other)?;
        if n > 0 {
            self.queue.push_back(out[..n].to_vec());
        }
        while let Some(n) = self.server.poll_block(&mut out).map_err(io::Error::other)? {
            self.queue.push_back(out[..n].to_vec());
        }
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let apdu = self
            .queue
            .pop_front()
            .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "nothing sent"))?;
        buf[..apdu.len()].copy_from_slice(&apdu);
        Ok(apdu.len())
    }
}

fn policy() -> SecurityPolicy {
    SecurityPolicy::authenticated_encrypted(SecuritySuite::Suite0)
}

fn hls_meter(server_gak: [u8; 16]) -> Meter {
    Server::new(
        ServerConfig {
            system_title: Some(SERVER_TITLE),
            mechanism: AuthMechanism::HighGmac,
            security: policy(),
            max_pdu_size: 512,
            ..Default::default()
        },
        TestMeter::default(),
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, server_gak), FixedRandom(0xB2)),
    )
}

fn hls_config(counter: u32) -> ClientConfig {
    ClientConfig {
        system_title: Some(CLIENT_TITLE),
        mechanism: AuthMechanism::HighGmac,
        security: policy(),
        max_pdu_size: 256,
        invocation_counter: counter,
        ..Default::default()
    }
}

fn hls_client(meter: Meter, counter: u32) -> Result<Client<InMemory, Provider>, ClientError> {
    Client::connect(
        InMemory { server: meter, queue: VecDeque::new() },
        hls_config(counter),
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xA1)),
    )
}

/// US1: the whole read of `examples/read.rs`, through the driver, over HLS-GMAC.
#[test]
fn a_meter_is_read_in_a_handful_of_calls() {
    let mut meter = hls_client(hls_meter(GAK), 0).unwrap();

    // Three registers in one round trip; one of them refused, by name, in its own slot.
    let list = meter
        .get_list(&[
            AttributeDescriptor::new(3, ENERGY, 2),
            AttributeDescriptor::new(1, SECRET_LOG, 2),
            AttributeDescriptor::new(8, CLOCK, 2),
        ])
        .unwrap();
    assert_eq!(list[0].as_ref().unwrap().as_u64(), Some(12_345_678));
    assert_eq!(list[1], Err(DataAccessResult::ReadWriteDenied));
    assert!(list[2].as_ref().unwrap().as_datetime().is_some());

    // A register's value with its scaler and unit, in one call.
    let energy = meter.read_scaled(3, ENERGY).unwrap();
    assert_eq!((energy.value, energy.scaler, energy.unit), (12_345_678, 0, Unit::WATT_HOUR));

    // The whole load profile — far larger than the 256-byte PDU size.
    let profile = meter.get(AttributeDescriptor::new(7, LOAD_PROFILE, 2)).unwrap();
    assert_eq!(profile.as_array().unwrap().len(), PROFILE_ROWS);

    // A selected range of it.
    let mut params = [0u8; 64];
    let selector = EntryDescriptor::entries(1, 10).to_selective_access(&mut params).unwrap();
    let ten = meter.get_selected(AttributeDescriptor::new(7, LOAD_PROFILE, 2), selector).unwrap();
    assert_eq!(ten.as_array().unwrap().len(), 10);

    // A method.
    assert_eq!(meter.action(MethodDescriptor::new(70, BREAKER, 1), None).unwrap(), None);
    assert_eq!(meter.get(AttributeDescriptor::new(70, BREAKER, 2)).unwrap(), DataBuf::Boolean(false));

    // A refusal is one error value naming the meter's reason.
    match meter.get(AttributeDescriptor::new(1, SECRET_LOG, 2)) {
        Err(ClientError::Refused(DataAccessResult::ReadWriteDenied)) => {}
        other => panic!("{other:?}"),
    }
    meter.release().unwrap();
}

/// US1-4: a SET value and an ACTION parameter far larger than one APDU go out in blocks —
/// GBT when negotiated, the service's own block form otherwise — and the outcome is one value.
#[test]
fn long_writes_and_long_method_parameters_go_out_in_blocks() {
    for conformance in [
        Conformance::CLIENT_DEFAULT,
        Conformance::CLIENT_DEFAULT.difference(Conformance::GENERAL_BLOCK_TRANSFER),
    ] {
        let mut meter = Client::<_, _, 8192>::connect(
            InMemory { server: hls_meter(GAK), queue: VecDeque::new() },
            ClientConfig { conformance, ..hls_config(0) },
            RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xA1)),
        )
        .unwrap();
        let image: Vec<u8> = (0..4096u32).map(|i| (i % 253) as u8).collect();
        meter.set(AttributeDescriptor::new(18, IMAGE, 2), &Data::OctetString(&image)).unwrap();
        assert_eq!(meter.get(AttributeDescriptor::new(18, IMAGE, 2)).unwrap().as_bytes(), Some(&image[..]));

        let echoed =
            meter.action(MethodDescriptor::new(18, IMAGE, 1), Some(&Data::OctetString(&image))).unwrap();
        assert_eq!(echoed.unwrap().as_bytes(), Some(&image[..]), "{conformance:?}");
    }
}

/// 001-large-transfers-driver/SR-008: the counter is taken explicitly and readable after
/// use, so it can be persisted.
#[test]
fn the_invocation_counter_is_explicit_and_readable() {
    let mut meter = hls_client(hls_meter(GAK), 10).unwrap();
    let after_connect = meter.invocation_counter();
    assert!(after_connect > 10, "the association itself used counters");
    for _ in 0..3 {
        meter.get(AttributeDescriptor::new(3, ENERGY, 2)).unwrap();
    }
    assert_eq!(meter.invocation_counter(), after_connect + 3);
}

/// 001-large-transfers-driver/SR-007: a meter that cannot prove it holds the key is not
/// read — the association call fails, and there is no client to read with.
#[test]
fn a_meter_with_the_wrong_key_fails_the_association() {
    let wrong = [0xEE; 16];
    match hls_client(hls_meter(wrong), 0) {
        Err(ClientError::Protocol(_) | ClientError::Exception(_) | ClientError::Rejected { .. }) => {}
        other => panic!("an unproven meter was accepted: {other:?}"),
    }
}

/// A transport that flips one byte of the `n`th reply — the meter's HLS proof, here.
struct Tamper {
    inner: InMemory,
    replies: usize,
    target: usize,
}

impl Transport for Tamper {
    fn send(&mut self, apdu: &[u8]) -> io::Result<()> {
        self.inner.send(apdu)
    }
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.recv(buf)?;
        self.replies += 1;
        if self.replies == self.target {
            buf[n - 1] ^= 0x01;
        }
        Ok(n)
    }
}

/// 001-large-transfers-driver/SR-007: the meter's own proof (HLS pass 4) is what decides.
/// Pass 3 succeeds — the meter accepted *our* proof — and its answer carrying f(StoC) is
/// corrupted in transit: the driver does not return a client.
#[test]
fn a_wrong_proof_from_the_meter_is_not_an_established_association() {
    let link =
        Tamper { inner: InMemory { server: hls_meter(GAK), queue: VecDeque::new() }, replies: 0, target: 2 };
    let result = Client::<_, _>::connect(
        link,
        hls_config(0),
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xA1)),
    );
    assert!(matches!(result, Err(ClientError::Protocol(_))), "{result:?}");
}

/// 001-large-transfers-driver/SR-009: formatting the driver and its errors shows no key.
#[test]
fn debug_output_carries_no_key_material() {
    let meter = hls_client(hls_meter(GAK), 0).unwrap();
    let text = format!("{meter:?}");
    let errors = [
        ClientError::Io(io::Error::other("x")),
        ClientError::Protocol(dlms_cosem_kit::codec::Error::new(dlms_cosem_kit::codec::ErrorKind::BadTag, 7)),
        ClientError::Rejected {
            result: dlms_cosem_kit::acse::AssociationResult::RejectedPermanent,
            diagnostic: dlms_cosem_kit::acse::Diagnostic::User(
                dlms_cosem_kit::acse::UserDiagnostic::AuthenticationFailure,
            ),
        },
        ClientError::Exception(dlms_cosem_kit::xdlms::ExceptionResponse {
            state_error: dlms_cosem_kit::xdlms::StateError::ServiceNotAllowed,
            service_error: dlms_cosem_kit::xdlms::ServiceError::InvocationCounterError,
            expected_invocation_counter: Some(42),
        }),
        ClientError::Refused(DataAccessResult::ReadWriteDenied),
        ClientError::ActionFailed(dlms_cosem_kit::xdlms::ActionResult::ReadWriteDenied),
        ClientError::Unexpected,
    ];
    let errors =
        format!("{errors:?} {}", errors.iter().map(ToString::to_string).collect::<Vec<_>>().join(" "));
    for key in [GUEK, GAK] {
        for rendering in
            [format!("{key:?}"), key.iter().map(|b| format!("{b:02x}")).collect(), format!("{:?}", &key[..4])]
        {
            assert!(!text.contains(&rendering) && !errors.contains(&rendering), "{rendering} leaked");
        }
    }
    assert!(text.contains("invocation_counter"));
}

// ---- over TCP, through the wrapper -------------------------------------------------------

/// Serve `meter` on a loopback socket, writing each reply `chunk` bytes at a time.
fn serve_wrapper(mut meter: Meter, chunk: usize, close_after: Option<usize>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let reassembler = StreamReassembler::new(u16::MAX);
        let mut buffered = Vec::new();
        let mut buf = [0u8; 4096];
        let mut sent = 0usize;
        loop {
            while let Ok(Some((wpdu, used))) = reassembler.next_pdu(&buffered) {
                let apdu = wpdu.apdu.to_vec();
                buffered.drain(..used);
                let mut out = vec![0u8; 8192];
                let mut replies = Vec::new();
                let n = meter.handle(&apdu, &mut out).unwrap();
                if n > 0 {
                    replies.push(out[..n].to_vec());
                }
                while let Some(n) = meter.poll_block(&mut out).unwrap() {
                    replies.push(out[..n].to_vec());
                }
                for reply in replies {
                    let mut framed = Vec::new();
                    Wpdu::new(0x01, 0x10, &reply).unwrap().encode(&mut framed).unwrap();
                    for piece in framed.chunks(chunk) {
                        if stream.write_all(piece).is_err() {
                            return;
                        }
                    }
                    sent += 1;
                    if close_after.is_some_and(|k| sent >= k) {
                        return;
                    }
                }
            }
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => buffered.extend_from_slice(&buf[..n]),
            }
        }
    });
    addr
}

/// US3-1: a meter that writes its answers a byte at a time is read the same.
#[test]
fn the_wrapper_transport_reassembles_a_trickled_answer() {
    let addr = serve_wrapper(hls_meter(GAK), 1, None);
    let link = WrapperTransport::connect(addr, 0x10, 0x01).unwrap();
    let mut meter: Client<_, _> = Client::connect(
        link,
        hls_config(0),
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xA1)),
    )
    .unwrap();
    let profile = meter.get(AttributeDescriptor::new(7, LOAD_PROFILE, 2)).unwrap();
    assert_eq!(profile.as_array().unwrap().len(), PROFILE_ROWS);
    meter.release().unwrap();
}

/// 001-large-transfers-driver/SR-006: a meter that accepts and never answers costs the
/// timeout, not a thread.
#[test]
fn a_silent_meter_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hold = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_secs(2));
        drop(stream);
    });
    let mut link = WrapperTransport::connect(addr, 0x10, 0x01).unwrap();
    link.set_timeout(Some(Duration::from_millis(200))).unwrap();
    let started = Instant::now();
    let result =
        Client::<_, _>::connect(link, ClientConfig::default(), RustCryptoProvider::new(KeyRing::default()));
    let elapsed = started.elapsed();
    match result {
        Err(ClientError::Io(e)) => {
            assert!(matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut), "{e}")
        }
        other => panic!("{other:?}"),
    }
    assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
    hold.join().unwrap();
}

/// Edge case: the meter closes the connection in the middle of a transfer.
#[test]
fn a_meter_closing_mid_transfer_is_an_io_error() {
    // Association takes two replies (AARE, HLS result); the third is the first block.
    let addr = serve_wrapper(hls_meter(GAK), 64, Some(3));
    let link = WrapperTransport::connect(addr, 0x10, 0x01).unwrap();
    let mut meter: Client<_, _> = Client::connect(
        link,
        hls_config(0),
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xA1)),
    )
    .unwrap();
    match meter.get(AttributeDescriptor::new(7, LOAD_PROFILE, 2)) {
        Err(ClientError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof, "{e}"),
        other => panic!("{other:?}"),
    }
}

// ---- over HDLC ---------------------------------------------------------------------------

/// Serve `meter` over HDLC on a loopback socket — a meter behind a TCP-to-serial bridge.
fn serve_hdlc(mut meter: Meter, max_info: u16) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let params = Parameters { max_info_tx: max_info, max_info_rx: max_info, ..Parameters::DEFAULT };
        let mut link = Connection::new(Role::Server, Address::server(1, 17), Address::client(0x10), params);
        let mut framer = Framer::new();
        let mut buffered = Vec::new();
        let mut storage = vec![0u8; 16384];
        let mut rx = hdlc::ReassemblyState::default();
        let mut outbox: VecDeque<Vec<u8>> = VecDeque::new();
        let read = |stream: &mut TcpStream, buffered: &mut Vec<u8>| -> bool {
            let mut b = [0u8; 1024];
            match stream.read(&mut b) {
                Ok(0) | Err(_) => false,
                Ok(n) => {
                    buffered.extend_from_slice(&b[..n]);
                    true
                }
            }
        };
        loop {
            let (event, consumed) = match framer.next_frame(&buffered) {
                Ok(Found::Frame { frame, consumed }) => {
                    let mut into = Reassembler::resume(&mut storage, rx);
                    let event = link.handle(&frame, &mut into).unwrap();
                    rx = into.state();
                    (event, consumed)
                }
                _ => {
                    if !read(&mut stream, &mut buffered) {
                        return;
                    }
                    continue;
                }
            };
            buffered.drain(..consumed);
            let mut out = vec![0u8; 512];
            match event {
                Event::AcknowledgeRequired => {
                    let n = link.acknowledge(&mut out).unwrap();
                    stream.write_all(&out[..n]).unwrap();
                }
                Event::PollRequired => {
                    // The client is waiting for the next segment of our reply.
                    if let Some(f) = outbox.pop_front() {
                        stream.write_all(&f).unwrap();
                    } else {
                        let n = link.poll(&mut out).unwrap();
                        stream.write_all(&out[..n]).unwrap();
                    }
                }
                Event::Lsdu => {
                    let lsdu = Reassembler::resume(&mut storage, rx).lsdu().to_vec();
                    rx = hdlc::ReassemblyState::default();
                    let mut reply = vec![0u8; 8192];
                    let mut replies = Vec::new();
                    let n = meter.handle(&lsdu[3..], &mut reply).unwrap();
                    if n > 0 {
                        replies.push(reply[..n].to_vec());
                    }
                    while let Some(n) = meter.poll_block(&mut reply).unwrap() {
                        replies.push(reply[..n].to_vec());
                    }
                    for apdu in replies {
                        let mut unit = hdlc::LLC_RESPONSE.to_vec();
                        unit.extend_from_slice(&apdu);
                        let mut seg = link.segmenter(&unit).unwrap();
                        while let Some(n) = link.next_frame(&mut seg, &mut out).unwrap() {
                            outbox.push_back(out[..n].to_vec());
                        }
                    }
                    while let Some(f) = outbox.pop_front() {
                        stream.write_all(&f).unwrap();
                    }
                }
                Event::Disconnected => return,
                _ => {}
            }
        }
    });
    addr
}

/// SC-005: the same read over HDLC, with only the transport line changed.
#[test]
fn the_same_read_runs_over_hdlc() {
    let addr = serve_hdlc(hls_meter(GAK), 128);
    let stream = TcpStream::connect(addr).unwrap();
    let params = Parameters { max_info_tx: 128, max_info_rx: 128, ..Parameters::DEFAULT };
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let link =
        HdlcTransport::connect_with(stream, Address::client(0x10), Address::server(1, 17), params).unwrap();
    let mut meter: Client<_, _> = Client::connect(
        link,
        hls_config(0),
        RustCryptoProvider::with_rng(KeyRing::new(GUEK, GAK), FixedRandom(0xA1)),
    )
    .unwrap();
    let profile = meter.get(AttributeDescriptor::new(7, LOAD_PROFILE, 2)).unwrap();
    assert_eq!(profile.as_array().unwrap().len(), PROFILE_ROWS);
    assert_eq!(meter.read_scaled(3, ENERGY).unwrap().value, 12_345_678);
    meter.release().unwrap();
}
