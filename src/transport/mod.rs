//! Transports: what carries an APDU.
//!
//! Each is sans-I/O. A transport turns bytes into APDUs and APDUs into bytes; opening a
//! socket, driving a serial port and waiting on a timer belong to the caller.
//!
//! * [`hdlc`] — the data link an optical probe, an RS-485 bus and many GPRS meters use.
//!   Framing that resynchronises on noise, segmentation, and a [`hdlc::Connection`] that
//!   drives the SNRM/UA handshake and the sequence numbers.
//! * [`wrapper`] — eight bytes of header over TCP or UDP, with bounded reassembly from a
//!   stream.
//! * [`p1`] — the customer interface. Not DLMS on the wire at all: it is the IEC 62056-21
//!   ASCII data readout that a Dutch or Belgian meter emits once a second. It lives here
//!   because it carries the same object model, so one crate and one set of types read
//!   both a P1 telegram and a ciphered push.
//!
//! None of the framing modules retransmits or times a peer out. That needs a clock, and
//! there is none in the sans-I/O core. With `std`, [`WrapperTransport`] and
//! [`HdlcTransport`] put that framing on a socket or a serial port, with a timeout, for
//! the [`Client`](crate::client::Client) driver.

#[cfg(feature = "hdlc")]
pub mod hdlc;
#[cfg(feature = "p1")]
pub mod p1;
#[cfg(feature = "wrapper")]
pub mod wrapper;

#[cfg(all(feature = "std", feature = "client", any(feature = "hdlc", feature = "wrapper")))]
mod link;
#[cfg(all(feature = "std", feature = "client", any(feature = "hdlc", feature = "wrapper")))]
pub use link::DEFAULT_TIMEOUT;
#[cfg(all(feature = "std", feature = "client", feature = "hdlc"))]
pub use link::HdlcTransport;
#[cfg(all(feature = "std", feature = "client", feature = "wrapper"))]
pub use link::WrapperTransport;
