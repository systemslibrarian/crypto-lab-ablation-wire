//! Which adversary each configuration actually survives.
//!
//! [`session`](crate::session) answers "what did the attacker recover". That is
//! a different question from "which attacker", and conflating them is the
//! ambiguity this module exists to remove: a channel is never *holding* in the
//! abstract, only holding against a named adversary and for a named asset. A
//! configuration that defeats a passive recorder can be trivially owned by an
//! active one, and the recovery verdict alone does not say so.
//!
//! The adversaries are A1–A5 from `THREAT_MODEL.md`, and the survival table in
//! that document is asserted against this module in `tests/ablation.rs` — so the
//! prose and the code cannot drift apart without a test going red.
//!
//! Every judgement carries a `because`. A red cross with no clause attached
//! teaches nothing: the point is not that a configuration fails but which
//! missing layer failed it.

use crate::session::Layers;

/// Whether a given adversary is defeated by a given configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The configuration defeats this adversary.
    Defended,
    /// This adversary wins.
    Exposed,
    /// Not defended, and not measured either. Distinct from `Exposed`, which is
    /// a claim; this is an admission.
    OutOfScope,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Defended => "defended",
            Status::Exposed => "exposed",
            Status::OutOfScope => "out-of-scope",
        }
    }
}

/// One adversary's standing against the current configuration.
#[derive(Debug, Clone, Copy)]
pub struct Adversary {
    pub id: &'static str,
    pub label: &'static str,
    pub status: Status,
    /// Why — naming the layer responsible, not merely the outcome.
    pub because: &'static str,
}

/// The first reason the traffic fails to resist someone who only reads it, in
/// the order an attacker would exploit them. `None` when it holds.
///
/// Three ways to lose, and the third is the one that needs stating: a repeated
/// nonce is harmless while the ratchet keeps handing out fresh keys, because two
/// frames then share a nonce and nothing else. It bites only when one key covers
/// both.
fn confidentiality_failure(l: Layers) -> Option<&'static str> {
    if !l.key_agreement {
        Some("key agreement is off, so the session key is a fixed value the observer holds too")
    } else if !l.aead {
        Some("nothing is encrypted — the wire carries the plaintext")
    } else if l.nonce_reuse && !l.ratchet {
        Some("a repeated nonce under a key that also repeats gives two ciphertexts sharing one keystream")
    } else {
        None
    }
}

/// Assess A1–A5 against a configuration.
///
/// `kem_is_pq` is the KEM *actually* in force, not the one requested — with key
/// agreement off the harness substitutes a static KEM, and reporting the
/// requested backend here would credit the channel with a property it does not
/// have.
pub fn assess(layers: Layers, kem_is_pq: bool) -> [Adversary; 5] {
    let conf = confidentiality_failure(layers);
    let holds = conf.is_none();

    let a1 = Adversary {
        id: "A1",
        label: "passive network observer",
        status: if holds { Status::Defended } else { Status::Exposed },
        because: conf.unwrap_or("AEAD under a key derived from a handshake the observer never saw"),
    };

    // Authentication is downstream of confidentiality: pinning an identity on a
    // channel whose contents are already readable defends nothing worth having.
    let a2 = Adversary {
        id: "A2",
        label: "active machine-in-the-middle",
        status: if holds && layers.authenticate {
            Status::Defended
        } else {
            Status::Exposed
        },
        because: match (conf, layers.authenticate) {
            (Some(why), _) => why,
            (None, false) => {
                "peer authentication is off, so the attacker's own correctly-signed hello is accepted"
            }
            (None, true) => "the responder's identity is pinned and the transcript is signed",
        },
    };

    let a3 = Adversary {
        id: "A3",
        label: "key compromise at time T",
        status: if holds && layers.ratchet {
            Status::Defended
        } else {
            Status::Exposed
        },
        because: match (conf, layers.ratchet) {
            (Some(why), _) => why,
            (None, false) => {
                "no ratchet — one key covers every message, so a compromise at T opens the whole archive"
            }
            (None, true) => {
                "the ratchet advances per message, so a compromise at T reaches forward but not back"
            }
        },
    };

    // A4 is a recording problem, so it does not depend on A2. A quantum
    // adversary arriving in 2040 cannot retroactively have been in the middle of
    // a handshake in 2026; they can only attack what they wrote down.
    let a4 = Adversary {
        id: "A4",
        label: "future quantum adversary",
        status: if holds && kem_is_pq {
            Status::Defended
        } else {
            Status::Exposed
        },
        because: match (conf, kem_is_pq) {
            (Some(why), _) => why,
            (None, false) => "X25519 alone — traffic recorded today falls when the discrete log does",
            (None, true) => "X-Wing holds if either of its two components survives",
        },
    };

    let a5 = Adversary {
        id: "A5",
        label: "local side-channel observer",
        status: Status::OutOfScope,
        because: "timing and cache behaviour are neither defended nor measured, and a WASM build makes no constant-time claim at all",
    };

    [a1, a2, a3, a4, a5]
}

/// Something an observer learns regardless of which layers are on.
#[derive(Debug, Clone, Copy)]
pub struct Leak {
    pub item: &'static str,
    pub detail: &'static str,
}

/// What stays visible on the wire in this configuration.
///
/// The transport layer must never be reported as simply "on", because the thing
/// it looks like it does — hide how long the message was — is precisely the
/// thing it does not do. `transport::obfuscate` writes the exact unpadded length
/// in the clear at offset 4, so quantising the total to a 64-byte block and then
/// announcing the real figure four bytes into the frame leaves the observer
/// better off than no padding at all would have.
pub fn metadata(layers: Layers) -> Vec<Leak> {
    let mut out = vec![
        Leak {
            item: "channel exists",
            detail: "padding and framing change which bytes appear, never the fact that a frame was sent",
        },
        Leak {
            item: "timing and frequency",
            detail:
                "when each frame went out, and how many — nothing here delays, batches or pads the schedule",
        },
    ];

    if layers.transport {
        out.push(Leak {
            item: "exact message length",
            detail: "the framing writes the unpadded length in the clear at offset 4, so padding to a 64-byte block quantises the total and then discloses the real figure anyway",
        });
        out.push(Leak {
            item: "frame structure",
            detail: "every frame opens with four 0xAA bytes — a fixed marker, trivially fingerprinted",
        });
    } else {
        out.push(Leak {
            item: "exact message length",
            detail: "the frame is the ciphertext: its length is the plaintext length plus a 16-byte tag",
        });
    }

    out
}
