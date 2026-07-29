//! Handshake transcript.
//!
//! Every byte that crosses the wire is absorbed here, and the resulting hash is
//! both signed by the responder and bound into the AEAD as associated data.
//! That binding is what stops an active attacker from splicing messages from
//! two sessions together — the transcript would differ and the tag would fail.

use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Transcript {
    h: Sha256,
}

impl Transcript {
    pub fn new(label: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(b"code-talker/transcript/v1");
        h.update((label.len() as u32).to_be_bytes());
        h.update(label);
        Transcript { h }
    }

    /// Absorb a labelled field. Length-prefixed so that concatenation is
    /// unambiguous — without this, ("ab","c") and ("a","bc") would collide.
    pub fn absorb(&mut self, label: &[u8], data: &[u8]) {
        self.h.update((label.len() as u32).to_be_bytes());
        self.h.update(label);
        self.h.update((data.len() as u32).to_be_bytes());
        self.h.update(data);
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.h.clone().finalize());
        out
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Transcript::new(b"default")
    }
}
