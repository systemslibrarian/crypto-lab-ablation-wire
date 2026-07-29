//! A real two-party handshake.
//!
//! Responder-authenticated, initiator-anonymous — the same shape as TLS with
//! server-only certificates. Two messages cross the wire and each side holds
//! only its own secrets. Neither function generates both keypairs.
//!
//! ```text
//!   Responder                                   Initiator
//!   ---------                                   ---------
//!   (id_sk, id_pk) long-term
//!   (kem_sk, kem_pk) ephemeral
//!   sig = Sign(id_sk, H(transcript))
//!            -- ResponderHello{id_pk, kem_pk, sig} -->
//!                                        verify sig over H(transcript)
//!                                        (ss, ct) = Encap(kem_pk)
//!            <-------- InitiatorReply{ct} ----------
//!   ss = Decap(kem_sk, ct)
//!
//!   root = HKDF(ss, info = "handshake" || H(full transcript))
//! ```
//!
//! The transcript hash is signed *and* bound into every AEAD as associated
//! data, so splicing messages between sessions fails the tag check.

use crate::error::{Error, Result};
use crate::identity::{self, Identity};
use crate::kdf;
use crate::kem::{Ciphertext, Kem, PublicKey, SecretKey};
use crate::transcript::Transcript;

#[derive(Clone, Debug)]
pub struct ResponderHello {
    pub identity_pk: Vec<u8>,
    pub kem_pk: PublicKey,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct InitiatorReply {
    pub ct: Ciphertext,
}

/// Established session state, identical on both sides if the handshake worked.
pub struct Handshake {
    pub root: [u8; 32],
    pub transcript_hash: [u8; 32],
    pub kem_name: &'static str,
    pub kem_is_pq: bool,
    pub authenticated: bool,
}

fn base_transcript(kem: &dyn Kem) -> Transcript {
    let mut t = Transcript::new(b"code-talker/handshake/v1");
    t.absorb(b"kem", kem.name().as_bytes());
    t
}

pub struct Responder<'a> {
    kem: &'a dyn Kem,
    identity: Identity,
    kem_sk: SecretKey,
    hello: ResponderHello,
    transcript: Transcript,
}

impl<'a> Responder<'a> {
    /// Generate ephemeral KEM material and sign it under the long-term identity.
    pub fn new(kem: &'a dyn Kem, identity: Identity) -> Result<Self> {
        let (kem_sk, kem_pk) = kem.keygen()?;

        let mut transcript = base_transcript(kem);
        let identity_pk = identity.public();
        transcript.absorb(b"id_pk", &identity_pk);
        transcript.absorb(b"kem_pk", kem_pk.as_bytes());

        // Sign the transcript, not the raw key. Signing the key alone would
        // leave the signature replayable into a different session.
        let signature = identity.sign(&transcript.hash());

        let hello = ResponderHello { identity_pk, kem_pk, signature };
        Ok(Responder { kem, identity, kem_sk, hello, transcript })
    }

    pub fn hello(&self) -> ResponderHello {
        self.hello.clone()
    }

    pub fn identity_public(&self) -> Vec<u8> {
        self.identity.public()
    }

    /// Consume the initiator's reply and derive the session root.
    pub fn accept(mut self, reply: &InitiatorReply, authenticated: bool) -> Result<Handshake> {
        let ss = self.kem.decapsulate(&self.kem_sk, &reply.ct)?;

        self.transcript.absorb(b"sig", &self.hello.signature);
        self.transcript.absorb(b"ct", reply.ct.as_bytes());
        let th = self.transcript.hash();

        let mut root = [0u8; 32];
        let mut info = Vec::with_capacity(9 + 32);
        info.extend_from_slice(b"handshake");
        info.extend_from_slice(&th);
        kdf::derive(ss.as_bytes(), &info, &mut root)?;

        Ok(Handshake {
            root,
            transcript_hash: th,
            kem_name: self.kem.name(),
            kem_is_pq: self.kem.is_pq(),
            authenticated,
        })
    }
}

/// Run the initiator side against a received hello.
///
/// `verify_identity` is the ablation switch. With it off the handshake still
/// completes — which is exactly the danger, because success is indistinguishable
/// from a session with an attacker in the middle.
pub fn initiate(
    kem: &dyn Kem,
    hello: &ResponderHello,
    verify_identity: bool,
    expected_identity: Option<&[u8]>,
) -> Result<(Handshake, InitiatorReply)> {
    let mut transcript = base_transcript(kem);
    transcript.absorb(b"id_pk", &hello.identity_pk);
    transcript.absorb(b"kem_pk", hello.kem_pk.as_bytes());

    if verify_identity {
        // Pinning: a valid signature from the wrong key is still the wrong peer.
        if let Some(expected) = expected_identity {
            if expected != hello.identity_pk.as_slice() {
                return Err(Error::Auth("identity key does not match the pinned peer"));
            }
        }
        identity::verify(&hello.identity_pk, &transcript.hash(), &hello.signature)?;
    }

    let (ss, ct) = kem.encapsulate(&hello.kem_pk)?;

    transcript.absorb(b"sig", &hello.signature);
    transcript.absorb(b"ct", ct.as_bytes());
    let th = transcript.hash();

    let mut root = [0u8; 32];
    let mut info = Vec::with_capacity(9 + 32);
    info.extend_from_slice(b"handshake");
    info.extend_from_slice(&th);
    kdf::derive(ss.as_bytes(), &info, &mut root)?;

    Ok((
        Handshake {
            root,
            transcript_hash: th,
            kem_name: kem.name(),
            kem_is_pq: kem.is_pq(),
            authenticated: verify_identity,
        },
        InitiatorReply { ct },
    ))
}
