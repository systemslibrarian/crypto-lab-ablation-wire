//! What the console says about itself, at the point where a reader needs it.
//!
//! The switches, the hexdump legend and the handshake table are all evidence,
//! and evidence with no caption is a reader's problem rather than a demo's
//! achievement. This module holds the captions: what each layer is for, which
//! adversary it answers, what its absence concretely does, and where the 1942
//! analogy stops being useful.
//!
//! **The layers are not a ladder.** Transport obfuscation, confidentiality,
//! authentication, forward secrecy and post-quantum resistance are not
//! interchangeable quantities with one of them strongest. They solve different
//! problems, and a reader who leaves believing they are ranked has learned
//! something false from a demo that switches them on and off in a column.
//!
//! Every panel here carries a [`Panel::demo`] — the configuration that shows the
//! consequence it describes — and the verdict that configuration actually
//! produces. `tests/ablation.rs` runs each one. An explanation that described a
//! failure the channel does not have would be the worst kind of thing to ship in
//! a teaching demo, because it is the part a reader cannot check for themselves.

use crate::lab::{full, no_aead, no_auth, no_key_agreement, no_ratchet, repeat_nonce, speaker, Setup};

/// One layer's caption, on the schema every layer answers.
#[derive(Debug, Clone, Copy)]
pub struct Panel {
    /// The console's switch id.
    pub id: &'static str,
    /// The security property it provides. For the injected fault, what it does.
    pub job: &'static str,
    /// Which adversary from `THREAT_MODEL.md` it answers.
    pub adversary: &'static str,
    /// The concrete consequence the console will show: for a layer, of switching
    /// it off; for the injected fault, of switching it on.
    pub consequence: &'static str,
    /// The configuration that demonstrates `consequence`, so the caption is a
    /// button rather than a paragraph.
    pub demo: Setup,
    /// The verdict `demo` actually produces. Asserted.
    pub demo_verdict: &'static str,
    /// Where the 1942 analogue helps, and where it stops.
    pub historical: &'static str,
    /// The modern protocol comparison, where one is honest.
    pub modern: &'static str,
}

/// Every demonstration hands the adversary a fluent speaker.
///
/// Without it the transport layer answers first and returns metadata for four of
/// the six panels, so a reader clicking "show me" on the key-agreement caption
/// would watch nothing happen and conclude key agreement was not load-bearing.
/// The transport layer is not a security boundary; an adversary who knows the
/// scheme is the only one worth demonstrating against.
const fn against_a_real_adversary() -> Setup {
    speaker(full())
}

pub const PANELS: [Panel; 6] = [
    Panel {
        id: "keyAgreement",
        job: "Establishes a secret the two endpoints share and nobody else holds, from messages an observer is welcome to read.",
        adversary: "A1 — a passive observer recording the wire",
        consequence: "Off, there is no secret to derive. The harness substitutes a fixed key, which is what a captured codebook is, and the observer rebuilds it from the transcript that crossed the wire in the clear. The AEAD still runs and still means nothing.",
        demo: no_key_agreement(against_a_real_adversary()),
        demo_verdict: "Plaintext",
        historical: "The codebook, and it is the layer the popular retelling leaves out. The analogy holds on the essential point — a secret distributed in advance, out of band — and stops at scale: a codebook is a fixed list carried in a satchel, where a KEM negotiates a fresh secret per session and forgets it afterwards.",
        modern: "The KEM half of a TLS 1.3 or Noise handshake. Here it is X-Wing or DHKEM(X25519), feeding HKDF-SHA256.",
    },
    Panel {
        id: "aead",
        job: "Makes the message unreadable without the key, and unmodifiable without detection. Two properties, one primitive, and the second is the one people forget.",
        adversary: "A1, and any attacker who would rather edit a message than read it",
        consequence: "Off, the frame carries the message. The transport layer still pads and frames it, so the wire looks transformed and is not — which is the exact mistake this demo exists to correct.",
        demo: no_aead(against_a_real_adversary()),
        demo_verdict: "Plaintext",
        historical: "The homophonic substitution: A could be sent as the word for ant, apple or axe. The analogy holds as concealment of content and stops hard at integrity — a substitution cipher has no tag, and a 1942 operator could not tell an altered transmission from a corrupted one.",
        modern: "AES-256-GCM or ChaCha20-Poly1305, with the handshake transcript bound in as associated data so a frame lifted from another session fails its tag check.",
    },
    Panel {
        id: "transport",
        job: "Pads to a block and wraps the result in a frame. This is not a security property and is not offered as one.",
        adversary: "Nobody. It costs an adversary who does not know the scheme one afternoon.",
        consequence: "Off, the frame is the raw ciphertext and the recovery does not change at all. That is the finding, not a disappointment: the layer everyone romanticises is the one whose absence the adversary does not notice.",
        demo: no_transport(against_a_real_adversary()),
        demo_verdict: "MetadataOnly",
        historical: "The rare unwritten language, and this is where the analogy is most often abused. Navajo was hard to recognise, not hard to break; the Japanese had a fluent speaker and got nothing, because the codebook was underneath. Rarity bought time, and time is worth having — it is just not confidentiality.",
        modern: "Closer to obfuscated transports like obfs4 or domain fronting than to anything in TLS: it raises the cost of classification, not of decryption.",
    },
    Panel {
        id: "authenticate",
        job: "Binds the handshake to a specific peer, by verifying a signature over the transcript against an identity key known in advance.",
        adversary: "A2 — an active attacker who can sit on the path, not merely watch it",
        consequence: "Off, the handshake still succeeds and the signature still verifies — because it is a valid signature, by the attacker. Both endpoints report a good session and one of them is the wrong party.",
        demo: no_auth(against_a_real_adversary()),
        demo_verdict: "MachineInTheMiddle",
        historical: "Absent in 1942, and the analogy is worth resisting: recognising a voice on the radio is authentication of a sort, but it is not a property the code itself provided, and no part of the code-talker system verified who was transmitting.",
        modern: "The certificate check in TLS. The pinning matters more than the signature: a signature nobody checks against a known key is a signature by whoever is talking.",
    },
    Panel {
        id: "ratchet",
        job: "Advances the message key by hashing it forward, so every message is sealed under a key used once. A symmetric hash ratchet — not the Signal Double Ratchet.",
        adversary: "A3 — someone who compromises a key at time T",
        consequence: "Off, one key covers every message the session ever sends, so a compromise at any point opens the whole archive. The recovery verdict does not move, and the threat matrix does: this is a property no single message can show you.",
        demo: no_ratchet(against_a_real_adversary()),
        demo_verdict: "MetadataOnly",
        historical: "Absent in 1942. A codebook was periodically reissued, which is key rotation on a schedule of weeks, not the per-message forward secrecy here.",
        modern: "The symmetric half of Signal's Double Ratchet, and only that half. It gives forward secrecy for message keys already deleted. It does not give post-compromise security — healing after a compromise needs fresh Diffie-Hellman input, and there is none here. Anyone holding the current chain key reads everything that follows.",
    },
    Panel {
        id: "nonceReuse",
        job: "Injects a fixed nonce on every frame. This is a fault, not a control — it is here because the failure it causes is the most instructive one in symmetric cryptography.",
        adversary: "A1, but only under a condition the switch alone does not create",
        consequence: "On, every frame is sealed under nonce 07…07. With the ratchet running that is survivable, because the key changes and two frames share a nonce and nothing else. With the ratchet off, one keystream encrypts two messages, XORing the ciphertexts cancels it, and a crib for message 1 yields message 2.",
        demo: repeat_nonce(no_ratchet(against_a_real_adversary())),
        demo_verdict: "KeystreamReuse",
        historical: "The nearest 1942 analogue is reusing a page of a one-time pad, which the Soviets did and which is how Venona happened. The mechanism is identical; only the primitive differs.",
        modern: "The reason AES-GCM is considered sharp-edged and why XChaCha20 and AES-GCM-SIV exist. Nonce uniqueness is a per-key requirement, and every real protocol enforces it with a counter rather than trusting a caller.",
    },
];

// `no_transport` has no other caller, so it lives here rather than in `lab`,
// where it would be an exported builder nothing built.
const fn no_transport(mut s: Setup) -> Setup {
    s.layers.transport = false;
    // With no transport layer there is nothing for a fluent speaker to strip, and
    // the console disables the switch. Leaving it set would put the panel's demo
    // into a state the console cannot represent.
    s.adversary_knows_transport = false;
    s
}

/// A term the page uses that a reader may not have.
#[derive(Debug, Clone, Copy)]
pub struct Term {
    pub term: &'static str,
    /// One sentence. Anything longer stops being a gloss and starts being a
    /// detour, and the reader is in the middle of something.
    pub definition: &'static str,
}

pub const GLOSSARY: [Term; 12] = [
    Term {
        term: "KEM",
        definition: "Key encapsulation mechanism: one side publishes a public key, the other generates a shared secret and an encapsulation of it, and only the holder of the private key can recover the secret.",
    },
    Term {
        term: "AEAD",
        definition: "Authenticated encryption with associated data: one primitive that both conceals a message and detects any modification to it, plus to context bound in alongside it.",
    },
    Term {
        term: "nonce",
        definition: "A number used once per key, mixed into encryption so the same plaintext under the same key does not produce the same ciphertext twice.",
    },
    Term {
        term: "transcript",
        definition: "The hash of every handshake message exchanged, in order, so that both sides can prove they saw the same conversation.",
    },
    Term {
        term: "associated data",
        definition: "Context authenticated by an AEAD but not encrypted by it — here the transcript hash, which is why a frame lifted from another session fails its tag check.",
    },
    Term {
        term: "pinning",
        definition: "Knowing a peer's identity key in advance, so that a signature can be checked against who you meant to talk to rather than merely against whoever is talking.",
    },
    Term {
        term: "ratchet",
        definition: "Advancing a key by a one-way function so the previous value cannot be recovered from the next one.",
    },
    Term {
        term: "forward secrecy",
        definition: "Compromising a key today does not expose messages sent before it, because the keys that protected them no longer exist.",
    },
    Term {
        term: "post-compromise security",
        definition: "Recovering security *after* a compromise, which needs fresh key material from outside the compromised chain — this demo's symmetric ratchet does not provide it.",
    },
    Term {
        term: "crib",
        definition: "A stretch of plaintext an attacker already knows or can guess, used as a lever against ciphertext that shares a keystream with it.",
    },
    Term {
        term: "metadata",
        definition: "Everything true about a message other than its contents — that it was sent, when, how often, and how long it was.",
    },
    Term {
        term: "harvest-now-decrypt-later",
        definition: "Recording encrypted traffic today in the expectation of decrypting it once a quantum computer exists, which is why confidentiality and authentication have different post-quantum deadlines.",
    },
];

/// What one labelled run of bytes in the hexdump is for.
#[derive(Debug, Clone, Copy)]
pub struct Field {
    /// Matches `Segment::kind` on the WASM surface.
    pub kind: &'static str,
    pub purpose: &'static str,
}

pub const FIELDS: [Field; 6] = [
    Field {
        kind: "framing",
        purpose: "Four 0xAA bytes marking the start of a frame. A fixed marker, and therefore a fingerprint: it identifies this protocol to anyone who has seen it once.",
    },
    Field {
        kind: "length",
        purpose: "The true unpadded body length, in the clear. This is why padding to a block quantises the frame and discloses the exact figure anyway.",
    },
    Field {
        kind: "ciphertext",
        purpose: "The message under AES-256-GCM or ChaCha20-Poly1305. Same length as the plaintext — a stream cipher construction adds no bulk, so the size is not hidden here either.",
    },
    Field {
        kind: "tag",
        purpose: "The 16-byte authentication tag over the ciphertext and the transcript hash. Alter either and this fails to verify, which is the difference between encryption and authenticated encryption.",
    },
    Field {
        kind: "plaintext",
        purpose: "The message itself, in the clear, because authenticated encryption is switched off. The framing around it is doing nothing but making it look otherwise.",
    },
    Field {
        kind: "padding",
        purpose: "Zero bytes rounding the frame up to a 64-byte block. It quantises the wire length and hides nothing about timing, frequency, or — given the length prefix above — the message size.",
    },
];

/// One step of the handshake as the console should draw it.
#[derive(Debug, Clone, Copy)]
pub struct Beat {
    pub from: &'static str,
    pub to: &'static str,
    pub message: &'static str,
    pub note: &'static str,
}

/// The handshake that actually ran.
///
/// Two shapes, and the difference is the whole authentication lesson: with a
/// pinned peer [`session::establish`](crate::session::establish) runs and the
/// attacker's hello is rejected before a channel exists; without one,
/// [`session::establish_mitm`](crate::session::establish_mitm) runs and the
/// party at the far end is the attacker. Naming the peer "Responder" in both
/// cases would draw the same picture for two different protocols.
pub fn sequence(authenticated: bool) -> [Beat; 4] {
    if authenticated {
        [
            Beat {
                from: "Responder",
                to: "Initiator",
                message: "hello { id_pk, kem_pk, sig }",
                note: "signs the transcript so far with its long-term identity key",
            },
            Beat {
                from: "Initiator",
                to: "",
                message: "verify sig against the pinned id_pk",
                note: "the pin is what makes this a check rather than a formality",
            },
            Beat {
                from: "Initiator",
                to: "Responder",
                message: "reply { ct }",
                note: "encapsulates a fresh shared secret to the responder's KEM key",
            },
            Beat {
                from: "both",
                to: "",
                message: "root = HKDF(ss, \"handshake\" || H(transcript))",
                note: "the intended peer holds the root, and nobody else does",
            },
        ]
    } else {
        [
            Beat {
                from: "Attacker",
                to: "Initiator",
                message: "hello { attacker id_pk, attacker kem_pk, sig }",
                note: "a correctly signed hello — signed by the attacker's own identity key",
            },
            Beat {
                from: "Initiator",
                to: "",
                message: "no pinned key, so nothing to verify against",
                note: "the signature is valid; validity was never the question",
            },
            Beat {
                from: "Initiator",
                to: "Attacker",
                message: "reply { ct }",
                note: "encapsulates a fresh shared secret to the attacker's KEM key",
            },
            Beat {
                from: "both",
                to: "",
                message: "root = HKDF(ss, \"handshake\" || H(transcript))",
                note: "the attacker holds the root, and both endpoints report success",
            },
        ]
    }
}
