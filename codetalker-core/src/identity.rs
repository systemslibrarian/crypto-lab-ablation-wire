//! Peer authentication.
//!
//! Without this, the channel is ephemeral-ephemeral with no binding to any
//! identity, and an active attacker sits in the middle of every session while
//! both endpoints report success. The 1942 stack had no equivalent layer at
//! all — nothing stopped an adversary from injecting traffic — which is why
//! its absence here would have been a conspicuous omission.
//!
//! ## Two suites, and why both exist
//!
//! A hybrid KEM protects *confidentiality* against a future quantum adversary:
//! traffic recorded today cannot be decrypted later. It does nothing for
//! *authentication*, which is a live property — an attacker needs the forgery
//! at the moment of the handshake, not in twenty years. So a build pairing
//! X-Wing with Ed25519 is not wrong, and against adversary A4 it is sufficient.
//!
//! It is, however, incomplete, and a crate that ships `pq` while signing with
//! Ed25519 invites a reader to assume more than it delivers. [`SigSuite`]
//! reports [`is_pq`](SigSuite::is_pq) truthfully for exactly that reason.

use crate::error::{Error, Result};

#[cfg(not(any(feature = "classical", feature = "pq")))]
compile_error!(
    "codetalker-core needs at least one of `classical` or `pq`: with neither there is no \
     signature scheme, and a handshake that cannot authenticate its peer is not something \
     this crate is willing to pretend to offer."
);

/// Signature suite. ML-DSA-65 (FIPS 204) under `pq`, Ed25519 (RFC 8032) under
/// `classical`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigSuite {
    Ed25519,
    MlDsa65,
}

impl SigSuite {
    pub fn name(&self) -> &'static str {
        match self {
            SigSuite::Ed25519 => "Ed25519",
            SigSuite::MlDsa65 => "ML-DSA-65",
        }
    }

    pub fn is_pq(&self) -> bool {
        match self {
            SigSuite::Ed25519 => false,
            SigSuite::MlDsa65 => true,
        }
    }

    /// Whether this build actually contains the suite. The wire format carries
    /// a suite name, so a peer can name one that was never compiled in.
    pub fn is_available(&self) -> bool {
        match self {
            SigSuite::Ed25519 => cfg!(feature = "classical"),
            SigSuite::MlDsa65 => cfg!(feature = "pq"),
        }
    }

    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "Ed25519" => Ok(SigSuite::Ed25519),
            "ML-DSA-65" => Ok(SigSuite::MlDsa65),
            _ => Err(Error::Auth("unknown signature suite")),
        }
    }

    /// The strongest suite this build contains. Post-quantum wins where it is
    /// available, so enabling `pq` upgrades authentication as well as key
    /// agreement rather than leaving one half classical by omission.
    pub fn preferred() -> Self {
        #[cfg(feature = "pq")]
        {
            SigSuite::MlDsa65
        }
        #[cfg(all(not(feature = "pq"), feature = "classical"))]
        {
            SigSuite::Ed25519
        }
    }

    pub fn available() -> Vec<SigSuite> {
        [SigSuite::Ed25519, SigSuite::MlDsa65]
            .into_iter()
            .filter(|s| s.is_available())
            .collect()
    }
}

/// A long-term signing identity.
///
/// Each variant is gated on the feature that provides it, so a suite that was
/// not compiled in cannot be constructed — as opposed to being constructed and
/// failing later, which is how a build ends up claiming a property it lacks.
pub enum Identity {
    #[cfg(feature = "classical")]
    Ed25519(Box<ed25519_dalek::SigningKey>),
    #[cfg(feature = "pq")]
    MlDsa65(Box<libcrux_ml_dsa::ml_dsa_65::MLDSA65KeyPair>),
}

/// Domain separation for ML-DSA, per FIPS 204. Binds a signature to this
/// protocol, so one cannot be lifted into another that happens to sign the
/// same bytes.
#[cfg(feature = "pq")]
pub const ML_DSA_CONTEXT: &[u8] = b"code-talker/handshake/v1";

fn random_32() -> [u8; 32] {
    use rand_core::RngCore;
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    seed
}

impl Identity {
    /// Generate an identity under the strongest suite this build contains.
    pub fn generate() -> Self {
        Self::generate_with(SigSuite::preferred()).expect("preferred() only names compiled suites")
    }

    /// Build an Ed25519 identity from a fixed seed.
    ///
    /// Exists for the RFC 8032 known-answer tests: Ed25519 is deterministic,
    /// which is the only reason a signature can be compared against a
    /// published vector at all. Never call this with anything but test data.
    #[cfg(feature = "classical")]
    pub fn from_ed25519_seed(seed: [u8; 32]) -> Self {
        Identity::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    pub fn generate_with(suite: SigSuite) -> Result<Self> {
        match suite {
            #[cfg(feature = "classical")]
            SigSuite::Ed25519 => Ok(Identity::Ed25519(Box::new(
                ed25519_dalek::SigningKey::from_bytes(&random_32()),
            ))),
            #[cfg(feature = "pq")]
            SigSuite::MlDsa65 => Ok(Identity::MlDsa65(Box::new(
                libcrux_ml_dsa::ml_dsa_65::generate_key_pair(random_32()),
            ))),
            #[allow(unreachable_patterns)]
            other => Err(unavailable(other)),
        }
    }

    pub fn suite(&self) -> SigSuite {
        match self {
            #[cfg(feature = "classical")]
            Identity::Ed25519(_) => SigSuite::Ed25519,
            #[cfg(feature = "pq")]
            Identity::MlDsa65(_) => SigSuite::MlDsa65,
        }
    }

    pub fn public(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "classical")]
            Identity::Ed25519(sk) => sk.verifying_key().to_bytes().to_vec(),
            #[cfg(feature = "pq")]
            Identity::MlDsa65(kp) => kp.verification_key.as_slice().to_vec(),
        }
    }

    /// Sign a message. Fallible, because ML-DSA can fail where Ed25519 has no
    /// equivalent failure mode.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            #[cfg(feature = "classical")]
            Identity::Ed25519(sk) => {
                use ed25519_dalek::Signer;
                Ok(sk.sign(msg).to_bytes().to_vec())
            }
            #[cfg(feature = "pq")]
            Identity::MlDsa65(kp) => {
                let sig = libcrux_ml_dsa::ml_dsa_65::sign(&kp.signing_key, msg, ML_DSA_CONTEXT, random_32())
                    .map_err(|_| Error::Auth("ml-dsa-65 signing failed"))?;
                Ok(sig.as_slice().to_vec())
            }
        }
    }
}

fn unavailable(suite: SigSuite) -> Error {
    match suite {
        SigSuite::Ed25519 => Error::BackendUnavailable("ed25519 (feature `classical`)"),
        SigSuite::MlDsa65 => Error::BackendUnavailable("ml-dsa-65 (feature `pq`)"),
    }
}

/// Verify a signature against a raw public key under a named suite.
///
/// The suite is a parameter rather than something inferred from key length,
/// because inferring it would let attacker-supplied bytes decide which
/// algorithm the verifier believes it is checking. `handshake` binds the suite
/// into the signed transcript, so naming the wrong one fails closed.
pub fn verify(suite: SigSuite, public: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    match suite {
        #[cfg(feature = "classical")]
        SigSuite::Ed25519 => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let pk: [u8; 32] = public
                .try_into()
                .map_err(|_| Error::Auth("bad identity key length"))?;
            let vk = VerifyingKey::from_bytes(&pk).map_err(|_| Error::Auth("malformed identity key"))?;
            let sb: [u8; 64] = sig.try_into().map_err(|_| Error::Auth("bad signature length"))?;
            vk.verify(msg, &Signature::from_bytes(&sb))
                .map_err(|_| Error::Auth("signature rejected"))
        }
        #[cfg(feature = "pq")]
        SigSuite::MlDsa65 => mldsa65_verify_raw(public, msg, sig, ML_DSA_CONTEXT),
        #[allow(unreachable_patterns)]
        other => Err(unavailable(other)),
    }
}

/// Raw ML-DSA-65 verification with an explicit context, for the FIPS 204
/// known-answer tests — ACVP signs with an empty context, not this protocol's.
#[cfg(feature = "pq")]
pub fn mldsa65_verify_raw(public: &[u8], msg: &[u8], sig: &[u8], context: &[u8]) -> Result<()> {
    use libcrux_ml_dsa::ml_dsa_65::{MLDSA65Signature, MLDSA65VerificationKey};
    const VK_LEN: usize = MLDSA65VerificationKey::len();
    const SIG_LEN: usize = MLDSA65Signature::len();

    let pk: [u8; VK_LEN] = public
        .try_into()
        .map_err(|_| Error::Auth("bad identity key length"))?;
    let sb: [u8; SIG_LEN] = sig.try_into().map_err(|_| Error::Auth("bad signature length"))?;

    libcrux_ml_dsa::ml_dsa_65::verify(
        &MLDSA65VerificationKey::new(pk),
        msg,
        context,
        &MLDSA65Signature::new(sb),
    )
    .map_err(|_| Error::Auth("signature rejected"))
}
