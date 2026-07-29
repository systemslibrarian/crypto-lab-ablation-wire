//! The layered channel, with each layer independently switchable.
//!
//! The point of this crate is not to build a secure channel. It is to let a
//! reader turn layers off and observe precisely what an adversary gains.

use crate::aead::{self, Suite, NONCE_LEN};
use crate::error::{Error, Result};
use crate::handshake::{self, Handshake};
use crate::identity::Identity;
use crate::kem::{Ciphertext, Kem, SecretKey};
use crate::ratchet::Chain;
use rand_core::RngCore;

/// Which layers are engaged. Maps onto the 1942 stack, plus the two layers
/// that stack never had.
#[derive(Debug, Clone, Copy)]
pub struct Layers {
    /// L1 — key agreement. 1942: the pre-shared codebook.
    pub key_agreement: bool,
    /// L2 — authenticated encryption. 1942: homophonic substitution.
    pub aead: bool,
    /// L3 — transport obfuscation. 1942: a rare unwritten language.
    pub transport: bool,
    /// Peer authentication. 1942: absent entirely.
    pub authenticate: bool,
    /// Symmetric ratchet. 1942: absent entirely.
    pub ratchet: bool,
    /// Repeat the nonce. Catastrophic, and one of the demo scenarios.
    pub nonce_reuse: bool,
}

impl Default for Layers {
    fn default() -> Self {
        Layers {
            key_agreement: true,
            aead: true,
            transport: true,
            authenticate: true,
            ratchet: true,
            nonce_reuse: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// Full plaintext. The channel failed.
    Plaintext(Vec<u8>),
    /// Keystream recovered via repeated nonce; plaintext follows from a crib.
    KeystreamReuse(Vec<u8>),
    /// An active attacker completed a handshake with both sides.
    MachineInTheMiddle(Vec<u8>),
    /// Nothing but length and timing.
    MetadataOnly,
}

impl Recovery {
    pub fn is_broken(&self) -> bool {
        !matches!(self, Recovery::MetadataOnly)
    }
}

/// A live channel: a completed handshake plus its sending chain.
pub struct Channel {
    pub hs: Handshake,
    chain: Chain,
    suite: Suite,
    ratchet: bool,
}

pub struct Frame {
    pub wire: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    /// The key this frame was sealed under. Exposed because the ablation
    /// harness and the demo both need to *show* it — that a fresh key appears
    /// per message is the ratchet's entire observable claim. It is still key
    /// material, so it is wiped when the frame goes out of scope.
    pub message_key: [u8; 32],
    pub counter: u32,
}

impl Drop for Frame {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.message_key.zeroize();
    }
}

pub const PAD_BLOCK: usize = 64;

impl Channel {
    pub fn new(hs: Handshake, suite: Suite, ratchet: bool) -> Self {
        let chain = Chain::new(hs.root);
        Channel { hs, chain, suite, ratchet }
    }

    /// Decrypt a frame from the peer.
    ///
    /// The receiving chain advances in lockstep with the sender's. If the two
    /// ever diverge, the message key is wrong and the tag rejects — which is
    /// the correct failure, not a bug to paper over.
    pub fn recv(&mut self, layers: Layers, frame: &Frame) -> Result<Vec<u8>> {
        let message_key = if self.ratchet {
            self.chain.next()?
        } else {
            self.chain.static_key()?
        };

        let body = if layers.transport {
            crate::transport::deobfuscate(&frame.wire)?
        } else {
            frame.wire.clone()
        };

        if !layers.aead {
            return Ok(body);
        }

        aead::open(
            self.suite,
            &message_key,
            &frame.nonce,
            &self.hs.transcript_hash,
            &body,
        )
    }

    /// Encrypt one message. The transcript hash goes in as associated data, so
    /// a frame lifted from another session fails its tag check.
    pub fn send(&mut self, layers: Layers, plaintext: &[u8]) -> Result<Frame> {
        let message_key = if self.ratchet {
            self.chain.next()?
        } else {
            self.chain.static_key()?
        };
        let counter = self.chain.n;

        // A fixed nonce, injected as a deliberate fault. On its own this is not
        // yet a break: it costs nothing until the *key* repeats as well. See
        // `adversary`, which is where that distinction is scored.
        let nonce = if layers.nonce_reuse {
            [7u8; NONCE_LEN]
        } else {
            let mut n = [0u8; NONCE_LEN];
            rand_core::OsRng.fill_bytes(&mut n);
            n
        };

        let body = if layers.aead {
            aead::seal(
                self.suite,
                &message_key,
                &nonce,
                &self.hs.transcript_hash,
                plaintext,
            )?
        } else {
            plaintext.to_vec()
        };

        let wire = if layers.transport {
            crate::transport::obfuscate(&body, PAD_BLOCK)
        } else {
            body
        };

        Ok(Frame { wire, nonce, message_key, counter })
    }
}

/// The KEM used when key agreement is switched off: a fixed keypair with a
/// fixed shared secret, which is what a captured codebook actually is.
static NO_AGREEMENT: crate::kem::StaticKem = crate::kem::StaticKem;

/// The KEM actually in force. With `key_agreement` off, the selected backend is
/// not used at all — the substitution happens here, where the secret is
/// established, rather than later where the attack is scored. That ordering is
/// the difference between an adversary who derives the key and one who is
/// handed it.
fn effective_kem(kem: &dyn Kem, layers: Layers) -> &dyn Kem {
    if layers.key_agreement {
        kem
    } else {
        &NO_AGREEMENT
    }
}

/// Establish a channel end to end, running both sides of a real handshake.
///
/// Returns the initiator's channel and the responder's, which must agree.
///
/// When `layers.key_agreement` is false the `kem` argument is ignored and
/// [`NO_AGREEMENT`] stands in, so `Handshake::kem_name` reports what the
/// channel is really built on rather than what the caller asked for.
pub fn establish(kem: &dyn Kem, layers: Layers, suite: Suite) -> Result<(Channel, Channel)> {
    let kem = effective_kem(kem, layers);
    let identity = Identity::generate();
    let responder = handshake::Responder::new(kem, identity)?;
    let hello = responder.hello();
    let pinned = responder.identity_public();

    let (init_hs, reply) = handshake::initiate(
        kem,
        &hello,
        layers.authenticate,
        if layers.authenticate { Some(&pinned) } else { None },
    )?;
    let resp_hs = responder.accept(&reply, layers.authenticate)?;

    Ok((
        Channel::new(init_hs, suite, layers.ratchet),
        Channel::new(resp_hs, suite, layers.ratchet),
    ))
}

/// Establish a channel against an attacker instead of the intended peer.
///
/// This is not a mock. The attacker runs a real [`handshake::Responder`] with
/// its own identity and its own KEM keypair, and the victim completes a real
/// handshake with it — the same shape as
/// `active_mitm_succeeds_when_authentication_is_off`, carried up to the channel
/// layer. Both sides report success, which is precisely the danger.
///
/// Returns `(victim, attacker)`. Only reachable with `layers.authenticate`
/// false: with a pinned peer, [`handshake::initiate`] rejects the attacker's
/// hello and no channel exists to return.
pub fn establish_mitm(kem: &dyn Kem, layers: Layers, suite: Suite) -> Result<(Channel, Channel)> {
    if layers.authenticate {
        return Err(Error::Auth(
            "a pinned peer leaves no room for a machine in the middle",
        ));
    }
    let kem = effective_kem(kem, layers);
    let attacker = handshake::Responder::new(kem, Identity::generate())?;
    let (victim_hs, reply) = handshake::initiate(kem, &attacker.hello(), false, None)?;
    let attacker_hs = attacker.accept(&reply, false)?;

    Ok((
        Channel::new(victim_hs, suite, layers.ratchet),
        Channel::new(attacker_hs, suite, layers.ratchet),
    ))
}

/// What an active attacker reads once it has become one of the two parties.
///
/// The attacker decrypts with a key it derived itself, through the ordinary
/// receive path, because it genuinely completed the handshake. Nothing is
/// granted to it that it did not negotiate.
pub fn adversary_mitm(attacker: &mut Channel, layers: Layers, frame: &Frame) -> Result<Recovery> {
    if layers.authenticate {
        return Err(Error::Auth(
            "a pinned peer leaves no room for a machine in the middle",
        ));
    }
    Ok(Recovery::MachineInTheMiddle(attacker.recv(layers, frame)?))
}

/// Model what a *passive* adversary recovers from one frame.
///
/// `adversary_knows_transport` is the Kieyoomia switch: it represents having a
/// linguist. Historically the Japanese had one and got nothing, because the
/// layer beneath was doing the work.
///
/// The active case lives in [`adversary_mitm`], which needs the channel the
/// attacker negotiated and so cannot be expressed here.
pub fn adversary(
    ch: &Channel,
    frame: &Frame,
    layers: Layers,
    adversary_knows_transport: bool,
) -> Result<Recovery> {
    // L3 is not a security boundary. Anyone who knows the scheme strips it.
    let body = if layers.transport {
        if !adversary_knows_transport {
            return Ok(Recovery::MetadataOnly);
        }
        crate::transport::deobfuscate(&frame.wire)?
    } else {
        frame.wire.clone()
    };

    if !layers.aead {
        // Obscurity only: the failure mode people mistake for the code talkers.
        return Ok(Recovery::Plaintext(body));
    }

    // No key agreement means there was no secret to agree, so the adversary
    // rebuilds the key rather than being handed it. Every input below is one it
    // genuinely holds: the transcript hash is computed from the two handshake
    // messages, both of which crossed the wire in the clear, and the shared
    // secret is a constant. Reading `frame.message_key` here instead would be
    // the simulation this crate exists to avoid.
    if !layers.key_agreement {
        let ss = NO_AGREEMENT.decapsulate(&SecretKey(Vec::new()), &Ciphertext(Vec::new()))?;

        let mut info = Vec::with_capacity(9 + 32);
        info.extend_from_slice(b"handshake");
        info.extend_from_slice(&ch.hs.transcript_hash);
        let mut root = [0u8; 32];
        crate::kdf::derive(ss.as_bytes(), &info, &mut root)?;

        // Walk the chain to this frame's counter. Without a ratchet there is
        // nothing to walk: one key covers every message ever sent.
        let mut chain = Chain::new(root);
        let message_key = if layers.ratchet {
            let mut mk = [0u8; 32];
            for _ in 0..frame.counter {
                mk = chain.next()?;
            }
            mk
        } else {
            chain.static_key()?
        };

        let pt = aead::open(
            ch.suite,
            &message_key,
            &frame.nonce,
            &ch.hs.transcript_hash,
            &body,
        )?;
        return Ok(Recovery::Plaintext(pt));
    }

    // Keystream reuse needs the *key* to repeat as well as the nonce. With the
    // ratchet on, every message is sealed under a fresh key, so a repeated
    // nonce never yields a two-time pad and the XOR recovers noise. Scoring
    // this on `nonce_reuse` alone would report a break that does not exist.
    // The ratchet earning its place is the point, not a footnote.
    if layers.nonce_reuse && !layers.ratchet {
        return Ok(Recovery::KeystreamReuse(body));
    }

    Ok(Recovery::MetadataOnly)
}

/// Recover a plaintext from two ciphertexts sharing a key and nonce.
/// Returns P2 given C1, C2 and a crib for P1. Bounded by the crib's length.
pub fn two_time_pad(ct1: &[u8], ct2: &[u8], crib: &[u8]) -> Vec<u8> {
    let n = ct1.len().min(ct2.len()).min(crib.len());
    (0..n).map(|i| ct1[i] ^ ct2[i] ^ crib[i]).collect()
}
