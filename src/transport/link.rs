//! Ready-made [`Transport`]s over `std::io`: the wrapper over TCP, and HDLC over any byte
//! stream.
//!
//! The framing underneath is the sans-I/O code in [`wrapper`](super::wrapper) and
//! [`hdlc`](super::hdlc); this module adds the socket, the read loop and a timeout. Both
//! transports bound everything a peer controls — the length a wrapper header announces,
//! the size of a reassembled HDLC unit — and default to a 30-second timeout, so a meter
//! that accepts a connection and then says nothing costs a head-end thread 30 seconds,
//! not forever.

use std::io::{self, Read, Write};
use std::net::TcpStream;
#[cfg(feature = "wrapper")]
use std::net::ToSocketAddrs;
use std::time::Duration;
#[cfg(feature = "hdlc")]
use std::vec;
use std::vec::Vec;

use crate::client::Transport;

/// How long a read or a write may block by default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest APDU a transport reassembles by default.
#[cfg(feature = "hdlc")]
const DEFAULT_MAX_APDU: usize = 0xFFFF;

fn invalid(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

fn protocol(e: crate::codec::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Read once into `chunk`, turning end-of-stream into an error that says so.
fn read_some<S: Read>(stream: &mut S, chunk: &mut [u8]) -> io::Result<usize> {
    match stream.read(chunk)? {
        0 => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the meter closed the connection")),
        n => Ok(n),
    }
}

fn deliver(apdu: &[u8], buf: &mut [u8]) -> io::Result<usize> {
    let slot = buf.get_mut(..apdu.len()).ok_or_else(|| invalid("an APDU larger than the receive buffer"))?;
    slot.copy_from_slice(apdu);
    Ok(apdu.len())
}

/// The DLMS wrapper (IEC 62056-4-7) over TCP: eight bytes of header per APDU.
///
/// The wrapper ports are the service access points: the client's (0x10 public client,
/// 0x20 reader, 0x30 management) and the logical device's (1 is management).
#[derive(Debug)]
#[cfg(feature = "wrapper")]
pub struct WrapperTransport {
    stream: TcpStream,
    client_wport: u16,
    server_wport: u16,
    reassembler: super::wrapper::StreamReassembler,
    buffered: Vec<u8>,
}

#[cfg(feature = "wrapper")]
impl WrapperTransport {
    /// Connect to `addr` and talk from `client_wport` to `server_wport`.
    ///
    /// # Errors
    /// When the connection or setting the default timeout fails.
    pub fn connect(addr: impl ToSocketAddrs, client_wport: u16, server_wport: u16) -> io::Result<Self> {
        Self::over(TcpStream::connect(addr)?, client_wport, server_wport)
    }

    /// Use a stream that is already connected.
    ///
    /// # Errors
    /// When setting the default timeout fails.
    pub fn over(stream: TcpStream, client_wport: u16, server_wport: u16) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let mut t = Self {
            stream,
            client_wport,
            server_wport,
            reassembler: super::wrapper::StreamReassembler::new(u16::MAX),
            buffered: Vec::new(),
        };
        t.set_timeout(Some(DEFAULT_TIMEOUT))?;
        Ok(t)
    }

    /// Bound how long a read or a write may block. `None` waits for ever.
    ///
    /// # Errors
    /// When the socket refuses the setting.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)?;
        self.stream.set_write_timeout(timeout)
    }
}

#[cfg(feature = "wrapper")]
impl Transport for WrapperTransport {
    fn send(&mut self, apdu: &[u8]) -> io::Result<()> {
        let mut framed = Vec::with_capacity(apdu.len().saturating_add(super::wrapper::Header::LEN));
        let wpdu = super::wrapper::Wpdu::new(self.client_wport, self.server_wport, apdu).map_err(protocol)?;
        crate::codec::Encode::encode(&wpdu, &mut framed).map_err(protocol)?;
        self.stream.write_all(&framed)
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut chunk = [0u8; 2048];
        loop {
            if let Some((wpdu, used)) = self.reassembler.next_pdu(&self.buffered).map_err(protocol)? {
                let n = deliver(wpdu.apdu, buf)?;
                self.buffered.drain(..used);
                return Ok(n);
            }
            let n = read_some(&mut self.stream, &mut chunk)?;
            self.buffered.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        }
    }

    fn close(&mut self) -> io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Both)
    }
}

/// HDLC (IEC 62056-46) over any byte stream: a serial port, an optical probe, or HDLC
/// tunnelled over TCP.
///
/// [`HdlcTransport::connect`] opens the link (SNRM/UA) with the parameters both ends agree;
/// every APDU is then segmented to the agreed information-field size on the way out and
/// reassembled on the way in, and [`Transport::close`] sends DISC.
///
/// Over a serial port the timeout is the port's own: set it on the stream before
/// connecting. Over TCP, [`HdlcTransport::set_timeout`] does it.
#[cfg(feature = "hdlc")]
pub struct HdlcTransport<S> {
    stream: S,
    link: super::hdlc::Connection,
    framer: super::hdlc::Framer,
    buffered: Vec<u8>,
    unit: Vec<u8>,
    rx: super::hdlc::ReassemblyState,
}

#[cfg(feature = "hdlc")]
impl<S> core::fmt::Debug for HdlcTransport<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HdlcTransport").field("state", &self.link.state()).finish_non_exhaustive()
    }
}

#[cfg(feature = "hdlc")]
impl<S: Read + Write> HdlcTransport<S> {
    /// Open an HDLC link from `client` to `server` over `stream`.
    ///
    /// # Errors
    /// When the meter does not confirm the link, or the stream fails.
    pub fn connect(
        stream: S,
        client: super::hdlc::Address,
        server: super::hdlc::Address,
    ) -> io::Result<Self> {
        Self::connect_with(stream, client, server, super::hdlc::Parameters::DEFAULT)
    }

    /// Open the link proposing `parameters` (information-field sizes and windows).
    ///
    /// # Errors
    /// As [`HdlcTransport::connect`].
    pub fn connect_with(
        stream: S,
        client: super::hdlc::Address,
        server: super::hdlc::Address,
        parameters: super::hdlc::Parameters,
    ) -> io::Result<Self> {
        let link = super::hdlc::Connection::new(super::hdlc::Role::Client, client, server, parameters);
        let mut t = Self {
            stream,
            link,
            framer: super::hdlc::Framer::new(),
            buffered: Vec::new(),
            unit: vec![0; DEFAULT_MAX_APDU.saturating_add(3)],
            rx: super::hdlc::ReassemblyState::default(),
        };
        let mut out = [0u8; 64];
        let n = t.link.connect(&mut out).map_err(protocol)?;
        t.stream.write_all(out.get(..n).unwrap_or(&[]))?;
        loop {
            match t.next_event()? {
                super::hdlc::Event::Connected => return Ok(t),
                super::hdlc::Event::Disconnected => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "the meter refused the HDLC link",
                    ));
                }
                _ => {}
            }
        }
    }

    /// The stream underneath.
    pub const fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Read until one frame arrives and say what it means. Reassembled information lands
    /// in `self.unit`.
    fn next_event(&mut self) -> io::Result<super::hdlc::Event> {
        let mut chunk = [0u8; 512];
        loop {
            match self.framer.next_frame(&self.buffered).map_err(protocol)? {
                super::hdlc::Found::Frame { frame, consumed } => {
                    let mut into = super::hdlc::Reassembler::resume(&mut self.unit, self.rx);
                    let event = self.link.handle(&frame, &mut into).map_err(protocol)?;
                    self.rx = into.state();
                    self.buffered.drain(..consumed);
                    return Ok(event);
                }
                super::hdlc::Found::Incomplete { discard } => {
                    self.buffered.drain(..discard.min(self.buffered.len()));
                    if self.buffered.len() > self.unit.len().saturating_mul(2) {
                        return Err(invalid("an HDLC frame larger than the link allows"));
                    }
                }
            }
            let n = read_some(&mut self.stream, &mut chunk)?;
            self.buffered.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        }
    }
}

#[cfg(feature = "hdlc")]
impl HdlcTransport<TcpStream> {
    /// Bound how long a read or a write may block. `None` waits for ever.
    ///
    /// # Errors
    /// When the socket refuses the setting.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)?;
        self.stream.set_write_timeout(timeout)
    }
}

#[cfg(feature = "hdlc")]
impl<S: Read + Write> Transport for HdlcTransport<S> {
    fn send(&mut self, apdu: &[u8]) -> io::Result<()> {
        let mut lsdu = Vec::with_capacity(apdu.len().saturating_add(3));
        lsdu.extend_from_slice(&super::hdlc::LLC_REQUEST);
        lsdu.extend_from_slice(apdu);
        let mut segmenter = self.link.segmenter(&lsdu).map_err(protocol)?;
        let mut out = vec![0u8; usize::from(self.link.parameters().max_info_tx).saturating_add(32)];
        // The segments of one unit go out back to back; only the last carries the
        // poll/final bit, which is what hands the line to the meter (see
        // `hdlc::Segmenter`).
        while let Some(n) = self.link.next_frame(&mut segmenter, &mut out).map_err(protocol)? {
            self.stream.write_all(out.get(..n).unwrap_or(&[]))?;
        }
        self.stream.flush()
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.next_event()? {
                super::hdlc::Event::Lsdu => {
                    let into = super::hdlc::Reassembler::resume(&mut self.unit, self.rx);
                    let apdu =
                        into.lsdu().get(3..).ok_or_else(|| invalid("an HDLC unit with no LLC header"))?;
                    let n = deliver(apdu, buf)?;
                    self.rx = super::hdlc::ReassemblyState::default();
                    return Ok(n);
                }
                super::hdlc::Event::PollRequired => {
                    let mut out = [0u8; 32];
                    let n = self.link.poll(&mut out).map_err(protocol)?;
                    self.stream.write_all(out.get(..n).unwrap_or(&[]))?;
                }
                super::hdlc::Event::Disconnected => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "the meter closed the HDLC link",
                    ));
                }
                _ => {}
            }
        }
    }

    fn close(&mut self) -> io::Result<()> {
        let mut out = [0u8; 32];
        let n = self.link.disconnect(&mut out).map_err(protocol)?;
        self.stream.write_all(out.get(..n).unwrap_or(&[]))?;
        // The UA is a courtesy; a meter that drops the line instead has closed it too.
        let _ = self.next_event();
        Ok(())
    }
}
