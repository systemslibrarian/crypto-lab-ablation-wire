//! Peer authentication.
//!
//! Without this, the channel is ephemeral-ephemeral with no binding to any
//! identity, and an active attacker sits in the middle of every session while
//! both endpoints report success. The 1942 stack had no equivalent layer at
//! all — nothing stopped an adversary from injecting traffic — which is why
//! its absence here would have been a conspicuous omission.

use crate::error::{Error, Result};

/// Signature suite. ML-DSA behind the `pq` feature; Ed25519 otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigSuite {
    Ed25519,
}

impl SigSuite {
    pub fn name(&self) -> &'static str {
        match self {
            SigSuite::Ed25519 => "Ed25519",
        }
    }
    pub fn is_pq(&self) -> bool {
        false
    }
}

/// A long-term signing identity.
#[cfg(feature = "classical")]
pub struct Identity {
    signing: ed25519_dalek::SigningKey,
}

#[cfg(feature = "classical")]
impl Identity {
    pub fn generate() -> Self {
        use ed25519_dalek::SigningKey;
        let mut seed = [0u8; 32];
        {
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut seed);
        }
        Identity { signing: SigningKey::from_bytes(&seed) }
    }

    pub fn public(&self) -> Vec<u8> {
        use ed25519_dalek::VerifyingKey;
        let vk: VerifyingKey = self.signing.verifying_key();
        vk.to_bytes().to_vec()
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        self.signing.sign(msg).to_bytes().to_vec()
    }

    pub fn suite(&self) -> SigSuite {
        SigSuite::Ed25519
    }
}

/// Verify a signature against a raw public key.
#[cfg(feature = "classical")]
pub fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk: [u8; 32] = public
        .try_into()
        .map_err(|_| Error::Auth("bad identity key length"))?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| Error::Auth("malformed identity key"))?;
    let sb: [u8; 64] = sig.try_into().map_err(|_| Error::Auth("bad signature length"))?;
    vk.verify(msg, &Signature::from_bytes(&sb))
        .map_err(|_| Error::Auth("signature rejected"))
}

#[cfg(not(feature = "classical"))]
pub fn verify(_public: &[u8], _msg: &[u8], _sig: &[u8]) -> Result<()> {
    Err(Error::BackendUnavailable("ed25519 (feature `classical`)"))
}
