//! A blocking client: the session, a transport, and every loop a meter read needs.
//!
//! [`ClientSession`] is sans-I/O and stays that way — it is what runs in firmware and under
//! an async runtime. This is the layer a head-end or a tool wants on top of it: one call
//! per service, with association (high-level security included), service-level block
//! transfer and general block transfer in both directions handled inside, and either owned values
//! or GET results borrowing caller-provided storage.
//!
//! ```no_run
//! use dlms_cosem_kit::client::{Client, ClientConfig, ClientError, Transport};
//! use dlms_cosem_kit::obis::Obis;
//! use dlms_cosem_kit::security::{KeyRing, RustCryptoProvider};
//!
//! // `link` is a `transport::WrapperTransport`, a `transport::HdlcTransport`, or your own.
//! fn read_energy(link: impl Transport) -> Result<(), ClientError> {
//!     let mut meter: Client<_, _> =
//!         Client::connect(link, ClientConfig::default(), RustCryptoProvider::os(KeyRing::default()))?;
//!     let energy = meter.read_scaled(3, Obis::new(1, 0, 1, 8, 0, 255))?;
//!     println!("{energy}");
//!     meter.release()?;
//!     Ok(())
//! }
//! ```

use std::io;
use std::vec;
use std::vec::Vec;

use crate::acse::{AssociationResult, Diagnostic};
use crate::axdr::{Data, DataBuf, ScaledValue, Unit};
use crate::codec::{Decode, Encode, Error, ErrorKind, SliceWriter, Writer};
use crate::obis::Obis;
use crate::security::CryptoProvider;
use crate::xdlms::{
    ActionResult, ApduTag, AttributeDescriptor, AttributeDescriptorWithSelection, Conformance,
    DataAccessResult, ExceptionResponse, GbtSender, InitiateResponse, MethodDescriptor, SelectiveAccess,
};

use super::{AssociationStep, ClientConfig, ClientSession, Response};

/// Something that carries one APDU at a time to a meter and back.
///
/// Framing is the transport's business — the wrapper header, HDLC frames and their
/// segmentation, a radio's own encapsulation — and so is reassembling a stream into whole
/// APDUs. Two operations rather than one request/response call, because a meter streaming
/// general-block-transfer blocks sends several APDUs for one request.
///
/// [`WrapperTransport`](crate::transport::WrapperTransport) and
/// [`HdlcTransport`](crate::transport::HdlcTransport) are the two this crate ships.
pub trait Transport {
    /// Send one APDU.
    ///
    /// # Errors
    /// When the link fails.
    fn send(&mut self, apdu: &[u8]) -> io::Result<()>;

    /// Receive one APDU into `buf`, returning its length.
    ///
    /// # Errors
    /// When the link fails, times out, or delivers an APDU larger than `buf`.
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Close the link after the association is released. The default does nothing.
    ///
    /// # Errors
    /// When the link fails.
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<T: Transport + ?Sized> Transport for &mut T {
    fn send(&mut self, apdu: &[u8]) -> io::Result<()> {
        (**self).send(apdu)
    }
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).recv(buf)
    }
    fn close(&mut self) -> io::Result<()> {
        (**self).close()
    }
}

impl<T: Transport + ?Sized> Transport for std::boxed::Box<T> {
    fn send(&mut self, apdu: &[u8]) -> io::Result<()> {
        (**self).send(apdu)
    }
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).recv(buf)
    }
    fn close(&mut self) -> io::Result<()> {
        (**self).close()
    }
}

/// Everything a [`Client`] call can fail with.
///
/// Every arm carries codes, results and offsets — never key material or a decrypted
/// payload — so an error can be logged as it is.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientError {
    /// The transport failed: a socket error, a timeout, a peer that closed the link.
    Io(io::Error),
    /// A malformed, unexpected or unverifiable APDU; the byte offset says where.
    Protocol(Error),
    /// The meter refused the association.
    Rejected {
        /// Its result.
        result: AssociationResult,
        /// Its reason.
        diagnostic: Diagnostic,
    },
    /// The meter refused the APDU itself. For a ciphered association the commonest cause
    /// is a stale invocation counter, and then `expected_invocation_counter` names the
    /// value to move to.
    Exception(ExceptionResponse),
    /// The meter refused a read or a write.
    Refused(DataAccessResult),
    /// A method did not run.
    ActionFailed(ActionResult),
    /// The response exceeded the configured byte budget.
    ResponseTooLarge {
        /// Maximum encoded result bytes for this call.
        limit: usize,
        /// An unfinished or unverified transfer was abandoned. Open a fresh connection.
        reconnect_required: bool,
    },
    /// A response of a kind the request cannot have.
    Unexpected,
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "transport: {e}"),
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Rejected { result, diagnostic } => {
                write!(f, "association rejected: {result:?} ({diagnostic:?})")
            }
            Self::Exception(e) => match e.expected_invocation_counter {
                Some(n) => write!(
                    f,
                    "the meter refused the request ({:?}); it expects invocation counter {n}",
                    e.service_error
                ),
                None => {
                    write!(f, "the meter refused the request: {:?} / {:?}", e.state_error, e.service_error)
                }
            },
            Self::Refused(r) => write!(f, "refused: {r:?}"),
            Self::ActionFailed(r) => write!(f, "method failed: {r:?}"),
            Self::ResponseTooLarge { limit, reconnect_required } => {
                write!(f, "response exceeds the {limit}-byte budget")?;
                if *reconnect_required {
                    f.write_str("; reconnect before retrying")?;
                }
                Ok(())
            }
            Self::Unexpected => f.write_str("a response of the wrong kind"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<Error> for ClientError {
    fn from(e: Error) -> Self {
        Self::Protocol(e)
    }
}

/// What a step of an exchange decided.
enum Step<R> {
    /// The answer.
    Done(R),
    /// Send `request[..n]` and keep going.
    Send(usize),
}

/// The bytes a [`Client`] keeps between calls, apart from the session.
struct Buffers {
    /// Where requests are built.
    request: Vec<u8>,
    /// Where responses are decrypted and GBT blocks gathered.
    response: Vec<u8>,
    /// One APDU as the transport delivered it.
    frame: Vec<u8>,
}

/// A blocking DLMS client over a [`Transport`].
///
/// `N` is the session's request buffer: the largest request it builds before block
/// transfer takes over. Single-value reads accept at most 64 KiB of encoded A-XDR data
/// by default. Set the limit with [`Client::with_response_capacity`] or supply a smaller
/// output slice to [`Client::get_into`]. Transport framing and protection use separate
/// workspace.
///
/// Call [`Client::release`] to release the association before dropping the client.
pub struct Client<T, P, const N: usize = 1024> {
    session: ClientSession<P, N>,
    transport: T,
    bufs: Buffers,
    value_limit: usize,
}

impl<T, P: CryptoProvider, const N: usize> core::fmt::Debug for Client<T, P, N> {
    /// The session's state and counters only: never the provider, whose keys these are,
    /// and never a buffer, which may hold a decrypted response.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("state", &self.session.state())
            .field("invocation_counter", &self.session.invocation_counter())
            .field("negotiated", &self.session.negotiated())
            .finish_non_exhaustive()
    }
}

/// Default limit in encoded result bytes.
const DEFAULT_RESPONSE_CAPACITY: usize = 64 * 1024;

/// What the GBT block header costs around its data, worst case.
const GBT_HEADER_MAX: usize = 1 + 1 + 2 + 2 + 3;

impl<T: Transport, P: CryptoProvider, const N: usize> Client<T, P, N> {
    /// Associate over `transport`, running every pass the mechanism needs.
    ///
    /// Returns only once the association is **established** — for high-level security,
    /// after the meter has proven it holds the key, not merely after it accepted ours.
    ///
    /// # Errors
    /// [`ClientError::Rejected`] or [`ClientError::Exception`] when the meter refuses;
    /// [`ClientError::Protocol`] when its proof does not verify; [`ClientError::Io`].
    pub fn connect(transport: T, config: ClientConfig, provider: P) -> Result<Self, ClientError> {
        let frame_len = usize::from(config.max_pdu_size).max(256).saturating_add(64);
        let mut client = Self {
            session: ClientSession::new(config, provider),
            transport,
            value_limit: DEFAULT_RESPONSE_CAPACITY,
            bufs: Buffers {
                request: vec![0; N.saturating_add(64)],
                response: vec![0; frame_len],
                frame: vec![0; frame_len],
            },
        };
        client.associate()?;
        Ok(client)
    }

    /// Set the maximum encoded value size for a GET, including its A-XDR type tag.
    /// The default is 64 KiB. The limit also bounds the encoded result list for a
    /// list GET and the encoded return value of an ACTION. A smaller caller buffer
    /// further limits a [`get_into`](Self::get_into) call.
    ///
    /// The configured receive PDU determines the frame size independently of this limit.
    /// GBT may stage up to the effective limit plus one receive frame for the
    /// protected APDU envelope. Set transport timeouts and wire budgets separately.
    #[must_use]
    pub fn with_response_capacity(mut self, bytes: usize) -> Self {
        self.value_limit = bytes;
        let ceiling = bytes.saturating_add(self.bufs.frame.len());
        if self.bufs.response.len() > ceiling {
            self.bufs.response.truncate(ceiling);
            self.bufs.response.shrink_to_fit();
        }
        self
    }

    fn associate(&mut self) -> Result<(), ClientError> {
        let n = self.session.associate_request(&mut self.bufs.request)?;
        self.transport.send(self.bufs.request.get(..n).unwrap_or(&[]))?;
        let m = self.transport.recv(&mut self.bufs.frame)?;
        let mut step = self.session.handle_associate_response(self.bufs.frame.get(..m).unwrap_or(&[]))?;
        if step == AssociationStep::HlsReplyRequired {
            let n = self.session.hls_reply_request(&mut self.bufs.request)?;
            self.transport.send(self.bufs.request.get(..n).unwrap_or(&[]))?;
            let m = self.transport.recv(&mut self.bufs.frame)?;
            step = self.session.handle_hls_reply_response(self.bufs.frame.get(..m).unwrap_or(&[]))?;
        }
        match step {
            AssociationStep::Established => Ok(()),
            AssociationStep::Rejected { result, diagnostic } => {
                Err(ClientError::Rejected { result, diagnostic })
            }
            AssociationStep::Exception(e) => Err(ClientError::Exception(e)),
            // A second "reply required" is a meter that will not finish the handshake.
            AssociationStep::HlsReplyRequired => Err(ClientError::Unexpected),
        }
    }

    /// Read an attribute.
    ///
    /// # Errors
    /// [`ClientError::Refused`] with the meter's reason, [`ClientError::ResponseTooLarge`]
    /// with the effective limit and recovery status, or a transport or protocol error.
    pub fn get(&mut self, attribute: AttributeDescriptor) -> Result<DataBuf, ClientError> {
        self.get_owned(attribute, None)
    }

    /// Read part of an attribute — a range of a profile, by entry or by date.
    ///
    /// # Errors
    /// As [`Client::get`].
    pub fn get_selected(
        &mut self,
        attribute: AttributeDescriptor,
        access: SelectiveAccess<'_>,
    ) -> Result<DataBuf, ClientError> {
        self.get_owned(attribute, Some(access))
    }

    /// Read one attribute, optionally selected, into caller-owned storage.
    ///
    /// The result borrows only `out`; the client can issue another request while the
    /// value is in use. The slice must fit the entire encoded value including its tag.
    /// On error its contents are unspecified.
    ///
    /// # Errors
    /// [`ClientError::ResponseTooLarge`] reports the effective limit. A completed,
    /// verified response leaves the association usable. If `reconnect_required` is
    /// true, the session is closed locally. [`ClientError::Refused`] preserves the
    /// meter's access result.
    pub fn get_into<'a>(
        &mut self,
        attribute: AttributeDescriptor,
        access: Option<SelectiveAccess<'_>>,
        out: &'a mut [u8],
    ) -> Result<Data<'a>, ClientError> {
        let limit = self.value_limit.min(out.len());
        let mut blocks = Blocks::new(SliceWriter::new(out), limit);
        self.read_value(
            attribute,
            access,
            &mut blocks,
            |writer, _, encoded| Ok(writer.write_bytes(encoded)?),
            |_| Ok(()),
        )?;
        Ok(Data::from_bytes(blocks.bytes.finish())?)
    }

    fn get_owned(
        &mut self,
        attribute: AttributeDescriptor,
        access: Option<SelectiveAccess<'_>>,
    ) -> Result<DataBuf, ClientError> {
        let mut blocks = Blocks::new(Vec::new(), self.value_limit);
        self.read_value(
            attribute,
            access,
            &mut blocks,
            |_, value, _| Ok(DataBuf::from_data(&value)?),
            |bytes| Ok(DataBuf::parse(bytes)?),
        )
    }

    /// Read several attributes in one round trip, one result each.
    ///
    /// A refused attribute does not fail the call: its slot holds the reason.
    ///
    /// # Errors
    /// When the whole request fails.
    pub fn get_list(
        &mut self,
        attributes: &[AttributeDescriptor],
    ) -> Result<Vec<Result<DataBuf, DataAccessResult>>, ClientError> {
        let items: Vec<_> = attributes
            .iter()
            .map(|d| AttributeDescriptorWithSelection { descriptor: *d, access: None })
            .collect();
        let n = self.session.get_request_with_list(&items, &mut self.bufs.request)?;
        let limit = self.value_limit;
        let mut blocks = Blocks::new(Vec::new(), limit);
        self.run(n, limit, |session, response, request, plain| {
            let results = match response {
                Response::DataList(results) if blocks.last == 0 => {
                    // The GET tag, choice and invoke id precede the encoded list.
                    blocks.check_size(plain.len().saturating_sub(3), true)?;
                    results
                }
                Response::Block { last, number, data } => {
                    blocks.push(number, last, data)?;
                    if !last {
                        return Ok(Step::Send(session.get_next_block_request(number, request)?));
                    }
                    crate::xdlms::List::<crate::xdlms::GetDataResult<'_>>::from_bytes(&blocks.bytes)?
                }
                Response::DataError(e) => return Err(ClientError::Refused(e)),
                _ => return Err(ClientError::Unexpected),
            };
            if results.len() != attributes.len() {
                return Err(ClientError::Unexpected);
            }
            let mut out = Vec::with_capacity(results.len());
            for result in results.iter() {
                out.push(match result?.value() {
                    Ok(d) => Ok(DataBuf::from_data(&d)?),
                    Err(e) => Err(e),
                });
            }
            Ok(Step::Done(out))
        })
    }

    /// Read a register's value with its scaler and unit — the attribute pair a register,
    /// an extended register and a demand register (classes 3, 4, 5) all carry as 2 and 3 —
    /// in one round trip.
    ///
    /// # Errors
    /// When either attribute is refused, or is not the shape a register's is.
    pub fn read_scaled(&mut self, class_id: u16, logical_name: Obis) -> Result<ScaledValue, ClientError> {
        let attrs = [
            AttributeDescriptor::new(class_id, logical_name, 2),
            AttributeDescriptor::new(class_id, logical_name, 3),
        ];
        let mut results = self.get_list(&attrs)?.into_iter();
        let value = results.next().ok_or(ClientError::Unexpected)?.map_err(ClientError::Refused)?;
        let scaler_unit = results.next().ok_or(ClientError::Unexpected)?.map_err(ClientError::Refused)?;
        let value = value.as_i64().ok_or(ClientError::Refused(DataAccessResult::TypeUnmatched))?;
        let [scaler, unit] = scaler_unit.as_structure().unwrap_or(&[]) else {
            return Err(ClientError::Refused(DataAccessResult::TypeUnmatched));
        };
        let scaler = scaler.as_i64().and_then(|s| i8::try_from(s).ok());
        let unit = unit.as_i64().and_then(|u| u8::try_from(u).ok());
        match (scaler, unit) {
            (Some(s), Some(u)) => Ok(ScaledValue::new(value, s, Unit(u))),
            _ => Err(ClientError::Refused(DataAccessResult::TypeUnmatched)),
        }
    }

    /// Write an attribute. A value too large for one APDU is sent in blocks.
    ///
    /// # Errors
    /// [`ClientError::Refused`] with the meter's reason; any transport or protocol error.
    pub fn set(&mut self, attribute: AttributeDescriptor, value: &Data<'_>) -> Result<(), ClientError> {
        let encoded = encode(value)?;
        let whole = self.session.set_request(attribute, None, *value, &mut self.bufs.request);
        let n = match whole {
            Ok(n) if self.fits(n) || self.gbt() => n,
            // Too large for one APDU and no GBT: the service's own block form, if agreed.
            Ok(_) | Err(Error { kind: ErrorKind::BufferTooSmall { .. }, .. }) => {
                let mut sender = self.session.set_transfer(attribute, None, &encoded)?;
                let n = self.session.next_block_request(&mut sender, &mut self.bufs.request)?;
                return self.run(n, self.value_limit, |session, response, request, _| match response {
                    Response::BlockAccepted { .. } => {
                        Ok(Step::Send(session.next_block_request(&mut sender, request)?))
                    }
                    Response::Ok => Ok(Step::Done(())),
                    Response::DataError(e) => Err(ClientError::Refused(e)),
                    _ => Err(ClientError::Unexpected),
                });
            }
            Err(e) => return Err(e.into()),
        };
        self.run(n, self.value_limit, |_, response, _, _| match response {
            Response::Ok => Ok(Step::Done(())),
            Response::DataError(e) => Err(ClientError::Refused(e)),
            _ => Err(ClientError::Unexpected),
        })
    }

    /// Invoke a method, returning what it returned. A parameter too large for one APDU is
    /// sent in blocks, and so is a return value too large for one.
    ///
    /// # Errors
    /// [`ClientError::ActionFailed`] with the method's result; any transport or protocol
    /// error.
    pub fn action(
        &mut self,
        method: MethodDescriptor,
        parameter: Option<&Data<'_>>,
    ) -> Result<Option<DataBuf>, ClientError> {
        let whole = self.session.action_request(method, parameter.copied(), &mut self.bufs.request);
        let mut blocks = Blocks::new(Vec::new(), self.value_limit);
        let n = match whole {
            Ok(n) if self.fits(n) || self.gbt() => n,
            Ok(_) | Err(Error { kind: ErrorKind::BufferTooSmall { .. }, .. }) => {
                let encoded = encode(parameter.ok_or(ClientError::Unexpected)?)?;
                let mut sender = self.session.action_transfer(method, &encoded)?;
                let n = self.session.next_block_request(&mut sender, &mut self.bufs.request)?;
                return self.run(n, self.value_limit, |session, response, request, plain| match response {
                    Response::BlockAccepted { .. } if !sender.is_done() => {
                        Ok(Step::Send(session.next_block_request(&mut sender, request)?))
                    }
                    other => action_outcome(session, other, request, &mut blocks, plain),
                });
            }
            Err(e) => return Err(e.into()),
        };
        self.run(n, self.value_limit, |session, response, request, plain| {
            action_outcome(session, response, request, &mut blocks, plain)
        })
    }

    /// Release the association and close the link, handing the transport back.
    ///
    /// After a capacity error that requires reconnecting, this only closes the old
    /// transport. Open a fresh connection for the next association.
    ///
    /// # Errors
    /// When the release cannot be sent. A meter that answers it with anything but a
    /// release response is still released from this end.
    pub fn release(mut self) -> Result<T, ClientError> {
        if self.session.state() == super::SessionState::Closed {
            self.transport.close()?;
            return Ok(self.transport);
        }
        let n = self.session.release_request(&mut self.bufs.request)?;
        self.transport.send(self.bufs.request.get(..n).unwrap_or(&[]))?;
        // The meter's answer is a courtesy; what matters is that this end stops.
        if let Ok(m) = self.transport.recv(&mut self.bufs.frame) {
            let _ = self
                .session
                .handle_response(self.bufs.frame.get(..m).unwrap_or(&[]), &mut self.bufs.response);
        }
        self.transport.close()?;
        Ok(self.transport)
    }

    /// The invocation counter this client will use next.
    ///
    /// **Persist it** before the process ends and pass it back as
    /// [`ClientConfig::invocation_counter`] next time: restarting from an old value under
    /// an unchanged key repeats GCM nonces, and a repeated nonce leaks the key's
    /// authentication subkey.
    #[must_use]
    pub const fn invocation_counter(&self) -> u32 {
        self.session.invocation_counter()
    }

    /// What the meter agreed to.
    #[must_use]
    pub const fn negotiated(&self) -> Option<&InitiateResponse> {
        self.session.negotiated()
    }

    /// The session underneath, for anything this layer does not wrap.
    #[must_use]
    pub const fn session(&self) -> &ClientSession<P, N> {
        &self.session
    }

    /// The session underneath, mutably.
    pub const fn session_mut(&mut self) -> &mut ClientSession<P, N> {
        &mut self.session
    }

    /// The transport underneath.
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    fn server_max(&self) -> usize {
        self.session.negotiated().map_or(usize::MAX, |n| match n.server_max_receive_pdu_size {
            0 => usize::MAX,
            size => usize::from(size),
        })
    }

    fn fits(&self, n: usize) -> bool {
        n <= self.server_max()
    }

    fn gbt(&self) -> bool {
        self.session
            .negotiated()
            .is_some_and(|n| n.negotiated_conformance.contains(Conformance::GENERAL_BLOCK_TRANSFER))
    }

    /// A value-returning read: whole, in service-level blocks, or over GBT.
    fn read_value<W: Writer, R>(
        &mut self,
        attribute: AttributeDescriptor,
        access: Option<SelectiveAccess<'_>>,
        blocks: &mut Blocks<W>,
        whole: impl Fn(&mut W, Data<'_>, &[u8]) -> Result<R, ClientError>,
        reassembled: impl Fn(&W) -> Result<R, ClientError>,
    ) -> Result<R, ClientError> {
        let n = self.session.get_request(attribute, access, &mut self.bufs.request)?;
        self.run(n, blocks.limit, |session, response, request, plain| match response {
            Response::Data(value) if blocks.last == 0 => {
                // The validated GetResponseNormal consists of tag, choice, invoke id,
                // success choice, then the original encoded Data through the end.
                let encoded = plain.get(4..).ok_or(ClientError::Unexpected)?;
                blocks.check_size(encoded.len(), true)?;
                Ok(Step::Done(whole(&mut blocks.bytes, value, encoded)?))
            }
            Response::DataError(e) => Err(ClientError::Refused(e)),
            Response::Block { last, number, data } => {
                blocks.push(number, last, data)?;
                if last {
                    Ok(Step::Done(reassembled(&blocks.bytes)?))
                } else {
                    Ok(Step::Send(session.get_next_block_request(number, request)?))
                }
            }
            _ => Err(ClientError::Unexpected),
        })
    }

    /// Send `request[..n]`, then feed every APDU that comes back to the session until
    /// `step` has its answer.
    ///
    /// GBT on the way in is invisible to `step`: blocks are gathered and acknowledged
    /// here, and `step` sees the reassembled response. Exceptions end the call.
    fn run<R>(
        &mut self,
        n: usize,
        limit: usize,
        mut step: impl FnMut(
            &mut ClientSession<P, N>,
            Response<'_>,
            &mut [u8],
            &[u8],
        ) -> Result<Step<R>, ClientError>,
    ) -> Result<R, ClientError> {
        let Self { session, transport, bufs, .. } = self;
        let server_max = session.negotiated().map_or(usize::MAX, |i| match i.server_max_receive_pdu_size {
            0 => usize::MAX,
            size => usize::from(size),
        });
        let gbt = session
            .negotiated()
            .is_some_and(|i| i.negotiated_conformance.contains(Conformance::GENERAL_BLOCK_TRANSFER));
        let mut pending = Some(n);
        loop {
            if let Some(n) = pending.take() {
                let request = bufs.request.get(..n).unwrap_or(&[]);
                if n > server_max && gbt {
                    send_as_gbt(
                        session,
                        transport,
                        request,
                        server_max,
                        &mut bufs.frame,
                        &mut bufs.response,
                    )?;
                } else {
                    transport.send(request)?;
                }
            }
            let m = transport.recv(&mut bufs.frame)?;
            let frame = bufs.frame.get(..m).ok_or(ClientError::Unexpected)?;
            let is_gbt = frame.first() == Some(&ApduTag::GeneralBlockTransfer.as_u8());
            // A protected GBT response must be staged until authentication completes.
            // Reserve only as blocks arrive and allow one frame for envelope overhead.
            let ceiling = limit.saturating_add(bufs.frame.len());
            if is_gbt {
                let wanted = session.received_gbt_bytes().saturating_add(m).min(ceiling);
                if wanted > bufs.response.len() {
                    let size = wanted.max(bufs.response.len().saturating_mul(2).min(ceiling));
                    bufs.response.reserve_exact(size.saturating_sub(bufs.response.len()));
                    bufs.response.resize(size, 0);
                }
            }
            let workspace_len = bufs.response.len().min(ceiling);
            let workspace = bufs.response.get_mut(..workspace_len).ok_or(ClientError::Unexpected)?;
            let (response, plain) = match session.handle_response_bytes(frame, workspace) {
                Err(Error { kind: ErrorKind::BufferTooSmall { .. }, .. }) if is_gbt => {
                    session.abandon();
                    return Err(ClientError::ResponseTooLarge { limit, reconnect_required: true });
                }
                result => result?,
            };
            match response {
                Response::Pending => {}
                Response::Acknowledge(ack) => transport.send(ack.as_bytes())?,
                Response::Exception(e) => return Err(ClientError::Exception(e)),
                other => match step(session, other, &mut bufs.request, plain) {
                    Ok(Step::Done(r)) => return Ok(r),
                    Ok(Step::Send(n)) => pending = Some(n),
                    Err(e) => {
                        if matches!(e, ClientError::ResponseTooLarge { reconnect_required: true, .. }) {
                            session.abandon();
                        }
                        return Err(e);
                    }
                },
            }
        }
    }
}

/// Send a request too large for the meter's PDU size as general block transfer, one block
/// per acknowledgement. The last block's answer is the response, left for the caller.
fn send_as_gbt<T: Transport, P: CryptoProvider, const N: usize>(
    session: &mut ClientSession<P, N>,
    transport: &mut T,
    request: &[u8],
    server_max: usize,
    frame: &mut [u8],
    response: &mut [u8],
) -> Result<(), ClientError> {
    let fragment = server_max.saturating_sub(GBT_HEADER_MAX);
    let mut sender = GbtSender::new(request, fragment, 1, false)?;
    let mut out = vec![0u8; fragment.saturating_add(GBT_HEADER_MAX)];
    loop {
        let Some((tag, rest)) = out.split_first_mut() else {
            return Err(ClientError::Protocol(Error::new(ErrorKind::BufferTooSmall { needed: 1 }, 0)));
        };
        let Some(n) = sender.next_block(rest)? else {
            return Err(ClientError::Unexpected);
        };
        *tag = ApduTag::GeneralBlockTransfer.as_u8();
        transport.send(out.get(..=n).unwrap_or(&[]))?;
        if usize::from(sender.block()) == usize::from(sender.blocks()) {
            return Ok(());
        }
        let m = transport.recv(frame)?;
        match session.handle_response(frame.get(..m).unwrap_or(&[]), response)? {
            Response::BlocksAcked { acked, window } => sender.acknowledge_with_window(acked, window)?,
            Response::Exception(e) => return Err(ClientError::Exception(e)),
            _ => return Err(ClientError::Unexpected),
        }
    }
}

/// Map an ACTION response, following a blocked return value to its end.
fn action_outcome<P: CryptoProvider, const N: usize>(
    session: &mut ClientSession<P, N>,
    response: Response<'_>,
    request: &mut [u8],
    blocks: &mut Blocks<Vec<u8>>,
    plain: &[u8],
) -> Result<Step<Option<DataBuf>>, ClientError> {
    match response {
        Response::Ok => Ok(Step::Done(None)),
        Response::ActionResult { result: ActionResult::Success, value } if blocks.last == 0 => {
            if value.is_some() {
                // Tag, choice, invoke id, action result, presence and data-result choice.
                blocks.check_size(plain.len().saturating_sub(6), true)?;
            }
            Ok(Step::Done(value.map(|v| DataBuf::from_data(&v)).transpose()?))
        }
        Response::ActionResult { result, .. } if !result.is_success() => {
            Err(ClientError::ActionFailed(result))
        }
        Response::Block { last, number, data } => {
            blocks.push(number, last, data)?;
            if last {
                Ok(Step::Done(Some(DataBuf::parse(&blocks.bytes)?)))
            } else {
                Ok(Step::Send(session.action_next_block_request(number, request)?))
            }
        }
        _ => Err(ClientError::Unexpected),
    }
}

/// A value arriving in service-level blocks, insisting they come consecutively from one.
///
/// A duplicated or reordered fragment concatenated in the wrong place usually still
/// decodes — into a value that is wrong and carries no error.
struct Blocks<W> {
    bytes: W,
    last: u32,
    limit: usize,
}

impl<W: Writer> Blocks<W> {
    fn new(bytes: W, limit: usize) -> Self {
        Self { bytes, last: 0, limit }
    }

    fn check_size(&self, additional: usize, last: bool) -> Result<(), ClientError> {
        if additional > self.limit.saturating_sub(self.bytes.written()) {
            return Err(ClientError::ResponseTooLarge { limit: self.limit, reconnect_required: !last });
        }
        Ok(())
    }

    fn push(&mut self, number: u32, last: bool, data: &[u8]) -> Result<(), ClientError> {
        if self.last.checked_add(1) != Some(number) || (!last && data.is_empty()) {
            return Err(ClientError::Protocol(Error::new(
                ErrorKind::UnexpectedMessage,
                self.bytes.written(),
            )));
        }
        self.check_size(data.len(), last)?;
        self.bytes.write_bytes(data)?;
        self.last = number;
        Ok(())
    }
}

fn encode(value: &Data<'_>) -> Result<Vec<u8>, ClientError> {
    let mut out = Vec::new();
    value.encode(&mut out)?;
    Ok(out)
}
