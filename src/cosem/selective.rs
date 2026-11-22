//! Selective access: which part of an attribute a read or a write means.
//!
//! The selector's meaning belongs to the interface class, so this is object-model
//! vocabulary; the application layer carries it (and re-exports it as
//! `xdlms::SelectiveAccess`).

use crate::axdr::Data;
use crate::codec::{Decode, Encode, Reader, Result, Writer};

/// A restriction on which part of an attribute is read or written.
///
/// The selector's meaning belongs to the interface class: for a profile generic,
/// selector 1 is a range of entries by capture-object value and selector 2 a range by
/// entry number.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelectiveAccess<'a> {
    /// Which selector of the class.
    pub selector: u8,
    /// Its parameters.
    pub parameters: Data<'a>,
}

impl Encode for SelectiveAccess<'_> {
    fn encode(&self, w: &mut dyn Writer) -> Result<()> {
        w.write_u8(self.selector)?;
        self.parameters.encode(w)
    }
}

impl<'a> Decode<'a> for SelectiveAccess<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self> {
        Ok(Self { selector: r.u8()?, parameters: Data::decode(r)? })
    }
}
