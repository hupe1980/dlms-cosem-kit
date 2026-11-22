//! General block transfer.
//!
//! GBT moves an APDU that does not fit the negotiated maximum size, in either
//! direction, independently of which service it carries. The procedure was rewritten in
//! Green Book edition 9 with an explicit window, a streaming sub-procedure and a retry
//! sub-procedure; this is that version.
//!
//! The block control byte packs three things: the last-block flag, the streaming flag,
//! and a six-bit window size. A window of zero is not "no window" — it is the value a
//! sender uses when it is not streaming, and treating it as a window of one is how a
//! streaming peer ends up waiting forever for an acknowledgement that is not coming.
//!
//! # How the window and streaming fields are read — derived
//!
//! The Green Book excerpt on disk does not print the GBT clauses, so this reading rests on
//! the crate's reading of the Ed 9 procedure and on one second implementation (Gurux,
//! which writes its own window setting into every block it emits, acknowledgements
//! included). It is labelled derived for that reason:
//!
//! * the **window** field announces the *sender's own receive window* — how many blocks
//!   it can take before it must acknowledge;
//! * the **streaming** bit says *more blocks of this window follow without an
//!   acknowledgement*. The block that clears it — or carries the last-block flag — is the
//!   one the receiver answers.
//!
//! The second rule is chosen because it cannot deadlock whichever way a peer reads the
//! first: a receiver acknowledges on the block the sender marks, and also when its own
//! window fills, so a sender that ignores the bit cannot overrun it either.

use crate::codec::{Decode, Encode, Error, ErrorKind, Reader, Result, SliceWriter, Writer};

/// The block control byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockControl(pub u8);

impl BlockControl {
    /// A control byte.
    #[must_use]
    pub const fn new(last_block: bool, streaming: bool, window: u8) -> Self {
        let mut v = window & 0x3F;
        if last_block {
            v |= 0x80;
        }
        if streaming {
            v |= 0x40;
        }
        Self(v)
    }

    /// True when no further block follows.
    #[must_use]
    pub const fn last_block(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// True when the sender is streaming: it will send a whole window without waiting.
    #[must_use]
    pub const fn streaming(self) -> bool {
        self.0 & 0x40 != 0
    }

    /// How many blocks the sender will send before it expects an acknowledgement.
    #[must_use]
    pub const fn window(self) -> u8 {
        self.0 & 0x3F
    }
}

/// One block of a general block transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneralBlockTransfer<'a> {
    /// Last-block flag, streaming flag and window size.
    pub control: BlockControl,
    /// This block's number, counting from one.
    pub block_number: u16,
    /// The highest block number the sender has received from the peer.
    pub block_number_ack: u16,
    /// The fragment of the carried APDU.
    pub block_data: &'a [u8],
}

impl GeneralBlockTransfer<'_> {
    /// An acknowledgement carrying no data, used to open the next window.
    #[must_use]
    pub const fn ack(block_number_ack: u16, window: u8) -> Self {
        Self {
            control: BlockControl::new(false, false, window),
            block_number: 0,
            block_number_ack,
            block_data: &[],
        }
    }
}

impl Encode for GeneralBlockTransfer<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u8(self.control.0)?;
        w.write_u16(self.block_number)?;
        w.write_u16(self.block_number_ack)?;
        w.write_length_prefixed(self.block_data)
    }
}

impl<'a> Decode<'a> for GeneralBlockTransfer<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self {
            control: BlockControl(r.u8()?),
            block_number: r.u16()?,
            block_number_ack: r.u16()?,
            block_data: r.length_prefixed()?,
        })
    }
}

/// The largest window a sender will use, which is what the six-bit field can carry.
pub const GBT_WINDOW_MAX: u8 = 0x3F;

/// The state of sending one APDU as GBT blocks, independent of where the APDU lives.
///
/// An engine cannot hold a [`GbtSender`] across calls, because the sender borrows the
/// APDU and the APDU lives in the engine. This is the same procedure with the bytes
/// passed in on every call, so it can be stored next to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GbtSendCursor {
    len: usize,
    /// The number of the last block emitted. Blocks count from one.
    block: u16,
    /// The highest block the peer has acknowledged.
    acked: u16,
    /// Bytes per block. Non-zero by construction: a `div_ceil` by a plain `usize` leaves a
    /// divide-by-zero panic path in the object code.
    fragment: core::num::NonZeroUsize,
    /// How many blocks may be outstanding: the peer's window, clamped to ours.
    send_window: u8,
    /// The window announced in our blocks: how many we can take.
    own_window: u8,
}

impl GbtSendCursor {
    /// A cursor over an APDU of `len` bytes, cut into blocks of at most `fragment` bytes.
    ///
    /// Until the peer announces a window the cursor sends one block at a time, which is
    /// the only rate a peer that has said nothing is known to accept.
    ///
    /// # Errors
    /// [`ErrorKind::InvalidLength`] when `fragment` is zero, which would never finish, or
    /// when the APDU needs more blocks than a sixteen-bit number can name.
    pub fn new(len: usize, fragment: usize, own_window: u8) -> Result<Self> {
        let Some(fragment) = core::num::NonZeroUsize::new(fragment) else {
            return Err(Error::new(ErrorKind::InvalidLength, 0));
        };
        if u16::try_from(len.div_ceil(fragment.get()).max(1)).is_err() {
            return Err(Error::new(ErrorKind::InvalidLength, 0));
        }
        let own_window = own_window.clamp(1, GBT_WINDOW_MAX);
        Ok(Self { len, block: 0, acked: 0, fragment, send_window: 1, own_window })
    }

    /// How many bytes the APDU being sent has.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True for an empty APDU, which is still sent as one (empty, last) block.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many blocks the whole APDU takes. An empty APDU is still one block: it has to
    /// be sent for the peer to learn that it is the last one.
    #[must_use]
    pub const fn blocks(&self) -> u16 {
        let n = self.len.div_ceil(self.fragment.get());
        if n == 0 { 1 } else { n as u16 }
    }

    /// True once the last block has been emitted.
    #[must_use]
    pub const fn is_sent(&self) -> bool {
        self.block >= self.blocks()
    }

    /// True when every block has been sent *and* acknowledged.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.acked >= self.blocks()
    }

    /// The number of the last block emitted; zero before the first.
    #[must_use]
    pub const fn block(&self) -> u16 {
        self.block
    }

    /// The highest block the peer has acknowledged.
    #[must_use]
    pub const fn acknowledged(&self) -> u16 {
        self.acked
    }

    /// Let `window` blocks be outstanding at once, as a peer that announced it would.
    /// Clamped to `1..=` [`GBT_WINDOW_MAX`].
    pub fn set_send_window(&mut self, window: u8) {
        self.send_window = window.clamp(1, GBT_WINDOW_MAX);
    }

    /// Emit the next block of `apdu`, or `None` when the window is full and an
    /// acknowledgement is owed first, or when every block has gone.
    ///
    /// `ack_of_peer` is what this end has received of the peer's own blocks — zero for a
    /// sender that is not also receiving.
    ///
    /// # Errors
    /// When `apdu` is not the length the cursor was made for, or `out` is too small.
    pub fn next_block(&mut self, apdu: &[u8], ack_of_peer: u16, out: &mut [u8]) -> Result<Option<usize>> {
        if apdu.len() != self.len {
            return Err(Error::new(ErrorKind::InvalidLength, 0));
        }
        let total = self.blocks();
        if self.block >= total {
            return Ok(None);
        }
        let outstanding = self.block.saturating_sub(self.acked);
        if outstanding >= u16::from(self.send_window) {
            return Ok(None);
        }
        let number = self.block.saturating_add(1);
        let start = usize::from(self.block).saturating_mul(self.fragment.get());
        let end = start.saturating_add(self.fragment.get()).min(self.len);
        let last = number == total;
        // More of this window follows when neither the window nor the APDU ends here.
        let window_ends = outstanding.saturating_add(1) >= u16::from(self.send_window);
        let streaming = !last && !window_ends;
        let frame = GeneralBlockTransfer {
            control: BlockControl::new(last, streaming, self.own_window),
            block_number: number,
            block_number_ack: ack_of_peer,
            block_data: apdu.get(start..end).unwrap_or(&[]),
        };
        let mut w = SliceWriter::new(out);
        frame.encode(&mut w)?;
        self.block = number;
        Ok(Some(w.written()))
    }

    /// Take the peer's acknowledgement, and the window it announced with it.
    ///
    /// One lower than the last block sent rewinds the cursor to just after it: that is
    /// the retry sub-procedure.
    ///
    /// # Errors
    /// [`ErrorKind::UnexpectedMessage`] when the peer acknowledges a block that was never
    /// sent, or one below what it has already acknowledged. The second bound is what keeps
    /// the retry finite: a peer that answers every window with a lower number than the
    /// last would leave the sender resending the same run for ever.
    pub fn acknowledge(&mut self, block_number_ack: u16, peer_window: u8) -> Result<()> {
        if block_number_ack > self.block || block_number_ack < self.acked {
            return Err(Error::new(ErrorKind::UnexpectedMessage, 0));
        }
        self.acked = block_number_ack;
        self.block = block_number_ack;
        // Zero is "not streaming": one block at a time.
        // The peer's window, never more than this end is configured to stream, and zero
        // ("not streaming") is one block at a time.
        self.set_send_window(peer_window.min(self.own_window));
        Ok(())
    }
}

/// Splits an APDU into general block transfer blocks, and takes acknowledgements back.
///
/// GBT is the *other* segmentation mechanism, and it is not a substitute for the
/// service-specific one: block transfer cuts a **value** into APDUs, GBT cuts an
/// **APDU** into blocks, and it does so for any service — including the ones that have
/// no blocked form of their own, which is the whole reason it exists.
///
/// This is [`GbtSendCursor`] borrowing its APDU, for callers that hold the bytes
/// themselves. The engines store the cursor.
///
/// ```
/// use dlms_cosem_kit::codec::Decode;
/// use dlms_cosem_kit::xdlms::{GbtAction, GbtReceiver, GbtSender, GeneralBlockTransfer};
///
/// let apdu = [0xC4u8; 300];                   // a get-response, too big for the link
/// let mut sender = GbtSender::new(&apdu, 100, 4, true)?;
/// let mut storage = [0u8; 512];
/// let mut receiver = GbtReceiver::new(&mut storage);
///
/// let mut frame = [0u8; 256];
/// while !sender.is_done() {
///     while let Some(n) = sender.next_block(&mut frame)? {
///         let block = GeneralBlockTransfer::from_bytes(&frame[..n])?;
///         if receiver.push(&block)? != GbtAction::Await {
///             sender.acknowledge(receiver.acknowledged())?;
///         }
///     }
/// }
/// assert_eq!(receiver.apdu(), &apdu[..]);
/// # Ok::<(), dlms_cosem_kit::Error>(())
/// ```
#[derive(Debug, Clone, Copy)]
pub struct GbtSender<'a> {
    apdu: &'a [u8],
    cursor: GbtSendCursor,
    window: u8,
}

impl<'a> GbtSender<'a> {
    /// Split `apdu` into blocks of at most `fragment` bytes.
    ///
    /// `window` is how many blocks may be outstanding when `streaming`; it is clamped to
    /// [`GBT_WINDOW_MAX`] and forced to one when not streaming.
    ///
    /// # Errors
    /// As [`GbtSendCursor::new`].
    pub fn new(apdu: &'a [u8], fragment: usize, window: u8, streaming: bool) -> Result<Self> {
        let window = if streaming { window.clamp(1, GBT_WINDOW_MAX) } else { 1 };
        let mut cursor = GbtSendCursor::new(apdu.len(), fragment, window)?;
        cursor.set_send_window(window);
        Ok(Self { apdu, cursor, window })
    }

    /// How many blocks the whole APDU takes.
    #[must_use]
    pub const fn blocks(&self) -> u16 {
        self.cursor.blocks()
    }

    /// True when every block has been sent *and* acknowledged.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.cursor.is_done()
    }

    /// The number of the last block emitted; zero before the first.
    #[must_use]
    pub const fn block(&self) -> u16 {
        self.cursor.block()
    }

    /// Emit the next block, or `None` when the window is full and an acknowledgement is
    /// owed first.
    ///
    /// # Errors
    /// When `out` is too small for the block.
    pub fn next_block(&mut self, out: &mut [u8]) -> Result<Option<usize>> {
        self.cursor.next_block(self.apdu, 0, out)
    }

    /// Take the peer's acknowledgement; see [`GbtSendCursor::acknowledge`].
    ///
    /// # Errors
    /// As [`GbtSendCursor::acknowledge`].
    pub fn acknowledge(&mut self, block_number_ack: u16) -> Result<()> {
        self.cursor.acknowledge(block_number_ack, self.window)
    }

    /// Take the peer's acknowledgement together with the window it announced.
    ///
    /// # Errors
    /// As [`GbtSendCursor::acknowledge`].
    pub fn acknowledge_with_window(&mut self, block_number_ack: u16, peer_window: u8) -> Result<()> {
        self.cursor.acknowledge(block_number_ack, peer_window)
    }
}

/// What a [`GbtReceiver`] wants done after a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GbtAction {
    /// The sender is streaming and its window is not full. Keep reading.
    Await,
    /// Send an acknowledgement carrying [`GbtReceiver::acknowledged`].
    Acknowledge,
    /// The APDU is complete; [`GbtReceiver::apdu`] has it. Acknowledge as well.
    Complete,
}

/// The state of reassembling one APDU from GBT blocks, independent of where it lands.
///
/// Out-of-order and duplicate blocks are answered rather than refused, because that is
/// what the retry sub-procedure is made of. A block ahead of the run is **not** stored:
/// acknowledging the last one received in order is how the receiver tells the sender
/// where to resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GbtRecvCursor {
    len: usize,
    /// The highest block received in order. Blocks count from one.
    received: u16,
    /// How many in-order blocks have arrived since the last acknowledgement.
    since_ack: u8,
    own_window: u8,
    complete: bool,
    /// An acknowledgement asking the sender to resume after `received` has gone out and
    /// nothing in order has arrived since.
    ///
    /// The rest of a window that broke keeps arriving after the gap; answering each of
    /// those blocks with the same retry request makes the sender rewind once per block,
    /// and the lost block crosses the link once per request.
    retry_requested: bool,
}

impl GbtRecvCursor {
    /// A cursor that will acknowledge at least every `own_window` blocks.
    #[must_use]
    pub const fn new(own_window: u8) -> Self {
        let own_window = if own_window == 0 {
            1
        } else if own_window > GBT_WINDOW_MAX {
            GBT_WINDOW_MAX
        } else {
            own_window
        };
        Self { len: 0, received: 0, since_ack: 0, own_window, complete: false, retry_requested: false }
    }

    /// Take one block into `buf`.
    ///
    /// `buf` must be the same buffer on every call of one transfer.
    ///
    /// # Errors
    /// [`ErrorKind::BufferTooSmall`] when the APDU does not fit, before anything is
    /// copied.
    pub fn push(&mut self, buf: &mut [u8], block: &GeneralBlockTransfer<'_>) -> Result<GbtAction> {
        if self.complete {
            // The previous APDU was taken; this is the start of the next one.
            self.reset();
        }
        let expected = self.received.saturating_add(1);
        if block.block_number != expected {
            // A duplicate the sender resent, or one from beyond a gap: say where the run
            // actually reaches and let the sender rewind to it — once. A retry request
            // already outstanding covers every other block of the broken window.
            if self.retry_requested {
                return Ok(GbtAction::Await);
            }
            self.retry_requested = true;
            self.since_ack = 0;
            return Ok(GbtAction::Acknowledge);
        }
        self.retry_requested = false;
        let at = self.len;
        let end = at.saturating_add(block.block_data.len());
        let capacity = buf.len();
        let slot = buf.get_mut(at..end).ok_or_else(|| {
            Error::new(ErrorKind::BufferTooSmall { needed: end.saturating_sub(capacity) }, at)
        })?;
        slot.copy_from_slice(block.block_data);
        self.len = end;
        self.received = block.block_number;
        self.since_ack = self.since_ack.saturating_add(1);

        if block.control.last_block() {
            self.complete = true;
            self.since_ack = 0;
            return Ok(GbtAction::Complete);
        }
        if !block.control.streaming() || self.since_ack >= self.own_window {
            self.since_ack = 0;
            return Ok(GbtAction::Acknowledge);
        }
        Ok(GbtAction::Await)
    }

    /// The block number to acknowledge: the highest received in order.
    #[must_use]
    pub const fn acknowledged(&self) -> u16 {
        self.received
    }

    /// The window this receiver announces.
    #[must_use]
    pub const fn window(&self) -> u8 {
        self.own_window
    }

    /// How many bytes have been gathered.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True before any block has been taken.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True once the last block has been stored.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Encode the acknowledgement this receiver owes.
    ///
    /// # Errors
    /// When `out` is too small.
    pub fn acknowledgement(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = SliceWriter::new(out);
        GeneralBlockTransfer::ack(self.received, self.own_window).encode(&mut w)?;
        Ok(w.written())
    }

    /// Discard everything, ready for the next APDU.
    pub const fn reset(&mut self) {
        self.len = 0;
        self.received = 0;
        self.since_ack = 0;
        self.complete = false;
        self.retry_requested = false;
    }
}

/// Reassembles an APDU from general block transfer blocks into a caller's buffer.
///
/// This is [`GbtRecvCursor`] holding its buffer, for callers that own one.
#[derive(Debug)]
pub struct GbtReceiver<'a> {
    buf: &'a mut [u8],
    cursor: GbtRecvCursor,
}

impl<'a> GbtReceiver<'a> {
    /// A receiver filling `buf`, acknowledging at least every [`GBT_WINDOW_MAX`] blocks.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, cursor: GbtRecvCursor::new(GBT_WINDOW_MAX) }
    }

    /// Take one block.
    ///
    /// # Errors
    /// [`ErrorKind::BufferTooSmall`] when the APDU does not fit.
    pub fn push(&mut self, block: &GeneralBlockTransfer<'_>) -> Result<GbtAction> {
        self.cursor.push(self.buf, block)
    }

    /// The block number to acknowledge: the highest received in order.
    #[must_use]
    pub const fn acknowledged(&self) -> u16 {
        self.cursor.acknowledged()
    }

    /// Encode the acknowledgement this receiver owes, announcing `window`.
    ///
    /// # Errors
    /// When `out` is too small.
    pub fn acknowledgement(&self, window: u8, out: &mut [u8]) -> Result<usize> {
        let mut w = SliceWriter::new(out);
        GeneralBlockTransfer::ack(self.cursor.acknowledged(), window).encode(&mut w)?;
        Ok(w.written())
    }

    /// The reassembled APDU. Empty until [`GbtReceiver::push`] has returned
    /// [`GbtAction::Complete`].
    #[must_use]
    pub fn apdu(&self) -> &[u8] {
        if self.cursor.is_complete() { self.buf.get(..self.cursor.len()).unwrap_or(&[]) } else { &[] }
    }

    /// How many bytes have been gathered, complete or not.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.cursor.len()
    }

    /// True before any block has been taken.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.cursor.is_empty()
    }

    /// Discard everything, ready for the next APDU.
    pub const fn reset(&mut self) {
        self.cursor.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_bits_are_independent() {
        let c = BlockControl::new(true, false, 7);
        assert!(c.last_block());
        assert!(!c.streaming());
        assert_eq!(c.window(), 7);
        assert_eq!(c.0, 0x87);

        let c = BlockControl::new(false, true, 0);
        assert!(!c.last_block());
        assert!(c.streaming());
        assert_eq!(c.window(), 0, "a window of zero is a value, not an absence");
        assert_eq!(c.0, 0x40);
    }

    #[test]
    fn a_block_round_trips() {
        let b = GeneralBlockTransfer {
            control: BlockControl::new(false, true, 4),
            block_number: 1,
            block_number_ack: 0,
            block_data: &[0xC4, 0x01, 0x81],
        };
        let mut buf = [0u8; 32];
        let mut w = crate::codec::SliceWriter::new(&mut buf);
        b.encode(&mut w).unwrap();
        assert_eq!(w.as_slice(), [0x44, 0x00, 0x01, 0x00, 0x00, 0x03, 0xC4, 0x01, 0x81]);
        assert_eq!(GeneralBlockTransfer::from_bytes(w.as_slice()).unwrap(), b);
    }

    /// The retry sub-procedure rewinds, and rewinding is bounded progress only while
    /// acknowledgements move forward. A peer that un-acknowledges a block it already
    /// acknowledged leaves the sender resending the same run for ever — and GBT has no
    /// clock behind it to notice, so the loop is the failure.
    #[test]
    fn an_acknowledgement_that_goes_backwards_is_refused() {
        let apdu = [0xC4u8; 300];
        let mut sender = GbtSender::new(&apdu, 100, 4, true).unwrap();
        let mut frame = [0u8; 256];
        while sender.next_block(&mut frame).unwrap().is_some() {}
        assert_eq!(sender.block(), 3);

        // A block that was never sent is not something an honest receiver names.
        assert_eq!(sender.acknowledge(4).unwrap_err().kind, ErrorKind::UnexpectedMessage);
        // One lower than the last sent is the retry rule, and is accepted.
        sender.acknowledge(2).unwrap();
        assert_eq!(sender.block(), 2, "and rewinds to just after it");
        // Going back below what is already acknowledged is not a retry.
        assert_eq!(sender.acknowledge(1).unwrap_err().kind, ErrorKind::UnexpectedMessage);
        assert!(sender.acknowledge(2).is_ok(), "repeating the same acknowledgement is harmless");
    }

    /// Drive a whole APDU across, one block at a time, with no streaming.
    #[test]
    fn an_apdu_crosses_block_by_block_and_comes_back_identical() {
        let apdu: alloc::vec::Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        for fragment in [1usize, 7, 128, 999, 1000, 1001] {
            let mut sender = GbtSender::new(&apdu, fragment, 1, false).unwrap();
            let mut storage = [0u8; 1100];
            let mut receiver = GbtReceiver::new(&mut storage);
            let mut frame = [0u8; 1100];
            let mut blocks = 0;
            while !sender.is_done() {
                let Some(n) = sender.next_block(&mut frame).unwrap() else {
                    panic!("a non-streaming sender must always have a block to send");
                };
                blocks += 1;
                let block = GeneralBlockTransfer::from_bytes(&frame[..n]).unwrap();
                let action = receiver.push(&block).unwrap();
                assert_ne!(action, GbtAction::Await, "a window of one acknowledges every block");
                sender.acknowledge(receiver.acknowledged()).unwrap();
            }
            assert_eq!(blocks, sender.blocks(), "at {fragment} bytes a block");
            assert_eq!(receiver.apdu(), &apdu[..], "at {fragment} bytes a block");
        }
    }

    /// Streaming: the sender puts a whole window on the wire before it waits.
    #[test]
    fn a_streaming_sender_fills_its_window_before_waiting() {
        let apdu = [0xAAu8; 500];
        let mut sender = GbtSender::new(&apdu, 50, 4, true).unwrap();
        let mut frame = [0u8; 128];
        // Four blocks go out with nothing coming back.
        for _ in 0..4 {
            assert!(sender.next_block(&mut frame).unwrap().is_some());
        }
        assert!(
            sender.next_block(&mut frame).unwrap().is_none(),
            "the fifth block waits for an acknowledgement"
        );
        sender.acknowledge(2).unwrap();
        // Two are now clear, so two more may go — and they are blocks 3 and 4 again,
        // because acknowledging 2 rewound the sender.
        let n = sender.next_block(&mut frame).unwrap().unwrap();
        assert_eq!(GeneralBlockTransfer::from_bytes(&frame[..n]).unwrap().block_number, 3);
    }

    /// The exit criterion for GBT: a dropped block is recovered by resuming after the
    /// last one that arrived, not by restarting the transfer.
    #[test]
    fn a_dropped_block_is_recovered_by_retry_rather_than_by_starting_again() {
        let apdu: alloc::vec::Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
        let mut sender = GbtSender::new(&apdu, 100, 6, true).unwrap();
        let mut storage = [0u8; 700];
        let mut receiver = GbtReceiver::new(&mut storage);
        let mut frame = [0u8; 256];

        let mut emitted = 0usize;
        let mut dropped_once = false;
        while !sender.is_done() {
            let Some(n) = sender.next_block(&mut frame).unwrap() else {
                sender.acknowledge(receiver.acknowledged()).unwrap();
                continue;
            };
            emitted += 1;
            let block = GeneralBlockTransfer::from_bytes(&frame[..n]).unwrap();
            // Lose block 3 exactly once. Everything after it arrives, and must not be
            // stored out of order.
            if block.block_number == 3 && !dropped_once {
                dropped_once = true;
                continue;
            }
            if receiver.push(&block).unwrap() != GbtAction::Await {
                sender.acknowledge(receiver.acknowledged()).unwrap();
            }
        }
        assert!(dropped_once);
        assert_eq!(receiver.apdu(), &apdu[..], "the APDU is whole and in order");
        assert!(emitted > 6, "the lost block and the ones after it were sent again");
        assert!(emitted < 6 * 3, "and the transfer did not restart from the beginning");
    }

    /// A receiver never stores a block from beyond a gap: acknowledging where the run
    /// really reaches is what makes the sender come back for the missing one, and
    /// keeping the future block as well would leave a hole nothing fills.
    #[test]
    fn a_block_from_beyond_a_gap_is_not_stored() {
        let mut storage = [0u8; 64];
        let mut receiver = GbtReceiver::new(&mut storage);
        let block = |n, last, data| GeneralBlockTransfer {
            control: BlockControl::new(last, false, 1),
            block_number: n,
            block_number_ack: 0,
            block_data: data,
        };
        assert_eq!(receiver.push(&block(1, false, &[1, 2])).unwrap(), GbtAction::Acknowledge);
        // Block 2 is lost; block 3 arrives.
        assert_eq!(receiver.push(&block(3, false, &[9, 9])).unwrap(), GbtAction::Acknowledge);
        assert_eq!(receiver.acknowledged(), 1, "the run still only reaches block one");
        assert_eq!(receiver.len(), 2, "and nothing from beyond the gap was kept");
        // A duplicate of what is already held changes nothing either — and asks for no
        // second retry, because one is already outstanding.
        assert_eq!(receiver.push(&block(1, false, &[1, 2])).unwrap(), GbtAction::Await);
        assert_eq!(receiver.len(), 2);
        // The retry closes the gap.
        assert_eq!(receiver.push(&block(2, false, &[3, 4])).unwrap(), GbtAction::Acknowledge);
        assert_eq!(receiver.push(&block(3, true, &[5, 6])).unwrap(), GbtAction::Complete);
        assert_eq!(receiver.apdu(), [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn an_acknowledgement_of_a_block_never_sent_is_refused() {
        let apdu = [0u8; 100];
        let mut sender = GbtSender::new(&apdu, 50, 1, false).unwrap();
        let mut frame = [0u8; 128];
        sender.next_block(&mut frame).unwrap();
        assert_eq!(sender.acknowledge(7).unwrap_err().kind, ErrorKind::UnexpectedMessage);
    }

    #[test]
    fn a_fragment_of_zero_would_never_finish() {
        assert_eq!(GbtSender::new(&[1, 2, 3], 0, 1, false).unwrap_err().kind, ErrorKind::InvalidLength);
    }

    fn blk(n: u16, last: bool, streaming: bool, data: &[u8]) -> GeneralBlockTransfer<'_> {
        GeneralBlockTransfer {
            control: BlockControl::new(last, streaming, 1),
            block_number: n,
            block_number_ack: 0,
            block_data: data,
        }
    }

    /// 001-large-transfers-driver/SR-003: a duplicated block is answered, never stored twice.
    #[test]
    fn a_duplicated_block_is_stored_once() {
        let mut buf = [0u8; 16];
        let mut rx = GbtRecvCursor::new(4);
        for (n, last) in [(1, false), (2, false), (2, false), (3, false), (4, false), (5, true)] {
            rx.push(&mut buf, &blk(n, last, true, &[n as u8])).unwrap();
        }
        assert!(rx.is_complete());
        assert_eq!(&buf[..rx.len()], [1, 2, 3, 4, 5]);
    }

    /// 001-large-transfers-driver/SR-002: a peer window is clamped to ours, and zero means
    /// one block at a time.
    #[test]
    fn a_peer_window_is_clamped_and_zero_means_one() {
        let apdu = [0u8; 1000];
        let mut out = [0u8; 64];
        let mut tx = GbtSendCursor::new(apdu.len(), 10, 4).unwrap();
        assert!(tx.next_block(&apdu, 0, &mut out).unwrap().is_some());
        assert!(tx.next_block(&apdu, 0, &mut out).unwrap().is_none(), "one block before the peer speaks");
        tx.acknowledge(1, 63).unwrap();
        let mut sent = 0;
        while tx.next_block(&apdu, 0, &mut out).unwrap().is_some() {
            sent += 1;
        }
        assert_eq!(sent, 4, "63 announced, 4 configured: 4 go");
        tx.acknowledge(5, 0).unwrap();
        assert!(tx.next_block(&apdu, 0, &mut out).unwrap().is_some());
        assert!(tx.next_block(&apdu, 0, &mut out).unwrap().is_none(), "window 0 is one block per ack");
    }

    /// The streaming bit marks every block of a window but the one the receiver answers.
    #[test]
    fn streaming_is_clear_on_the_block_that_ends_a_window() {
        let apdu = [0u8; 100];
        let mut out = [0u8; 64];
        let mut tx = GbtSendCursor::new(apdu.len(), 10, 3).unwrap();
        tx.set_send_window(3);
        let mut flags = alloc::vec::Vec::new();
        while let Some(n) = tx.next_block(&apdu, 0, &mut out).unwrap() {
            let b = GeneralBlockTransfer::from_bytes(&out[..n]).unwrap();
            flags.push(b.control.streaming());
            assert_eq!(b.control.window(), 3, "the window field is our own");
        }
        assert_eq!(flags, [true, true, false]);
    }

    /// 001-large-transfers-driver/SR-001: a block that would overflow is refused before it
    /// is copied, and nothing already gathered moves.
    #[test]
    fn an_overflowing_block_is_refused_before_copying() {
        let mut buf = [0u8; 4];
        let mut rx = GbtRecvCursor::new(4);
        rx.push(&mut buf, &blk(1, false, false, &[1, 2, 3])).unwrap();
        let e = rx.push(&mut buf, &blk(2, true, false, &[4, 5])).unwrap_err();
        assert!(matches!(e.kind, ErrorKind::BufferTooSmall { needed: 1 }));
        assert_eq!(rx.len(), 3);
        assert_eq!(buf, [1, 2, 3, 0]);
    }

    #[test]
    fn a_receiver_acknowledges_when_its_own_window_fills_even_if_the_sender_keeps_streaming() {
        let mut buf = [0u8; 16];
        let mut rx = GbtRecvCursor::new(2);
        assert_eq!(rx.push(&mut buf, &blk(1, false, true, &[1])).unwrap(), GbtAction::Await);
        assert_eq!(rx.push(&mut buf, &blk(2, false, true, &[2])).unwrap(), GbtAction::Acknowledge);
    }
}
