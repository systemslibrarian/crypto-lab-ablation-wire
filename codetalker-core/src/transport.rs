//! Layer 3: transport obfuscation.
//!
//! DELIBERATELY WEAK. This pads and reframes; it is not obfs4 and does not try
//! to be. The pedagogical claim of this crate is that L3 sits *outside* the
//! security boundary, and a convincing obfuscator would obscure that claim by
//! making the channel look safe when the layers beneath it are off.
//!
//! Anything relying on this for confidentiality is misusing it.

use crate::error::{Error, Result};

const FRAME: u8 = 0xAA;

/// Pad to a fixed block multiple and wrap in framing bytes.
pub fn obfuscate(data: &[u8], block: usize) -> Vec<u8> {
    let pad_len = if block == 0 {
        0
    } else {
        (block - (data.len() % block)) % block
    };
    let mut out = Vec::with_capacity(data.len() + pad_len + 8);
    out.extend_from_slice(&[FRAME; 4]);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out.extend(core::iter::repeat_n(0u8, pad_len));
    out
}

/// Strip framing and padding. Any observer who knows the scheme can do this.
pub fn deobfuscate(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 8 || data[..4] != [FRAME; 4] {
        return Err(Error::Transport("bad framing"));
    }
    let len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let body = &data[8..];
    if body.len() < len {
        return Err(Error::Transport("truncated"));
    }
    Ok(body[..len].to_vec())
}

/// What a passive observer learns even when every layer is on: size and shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observed {
    pub wire_len: usize,
    pub padded_to: usize,
}

pub fn observe(wire: &[u8], block: usize) -> Observed {
    Observed { wire_len: wire.len(), padded_to: block }
}
