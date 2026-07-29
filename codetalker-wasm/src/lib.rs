//! Browser surface for the code-talker ablation demo.
//!
//! Build with:
//!   wasm-pack build codetalker-wasm --target web --release --out-dir ../web/pkg
//!
//! This module holds no cryptographic logic of its own. Every value it reports
//! comes back from `codetalker-core` — including the adversary's verdict, which
//! is computed by the same code the ablation tests exercise. The page renders
//! what it is told and decides nothing.

use codetalker_core::session::{self, Recovery};
use codetalker_core::{aead, kem, transport};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

fn js(e: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// One switch per [`session::Layers`] field, plus the choices the harness makes
/// available. Field-for-field with the core type, so a change there surfaces
/// here as a compile error rather than a silently ignored toggle.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub plaintext: String,
    /// A second message, sent on the same channel. Both the ratchet and the
    /// two-time pad are claims about the *relationship between* consecutive
    /// messages; neither can be shown with one.
    pub second_message: String,
    pub backend: String,
    pub suite: String,
    pub key_agreement: bool,
    pub aead: bool,
    pub transport: bool,
    pub authenticate: bool,
    pub ratchet: bool,
    pub nonce_reuse: bool,
    /// The Kieyoomia switch: the adversary has a fluent speaker.
    pub adversary_knows_transport: bool,
}

/// A labelled run of bytes on the wire, so the page can colour the hexdump
/// without re-deriving the frame format in JavaScript.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Segment {
    pub kind: &'static str,
    pub label: &'static str,
    pub hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameView {
    pub wire: String,
    pub wire_len: usize,
    pub nonce: String,
    pub message_key: String,
    pub counter: u32,
    /// Ciphertext with the tag stripped — what a two-time pad operates on.
    pub ciphertext: String,
    pub segments: Vec<Segment>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Transmission {
    /// The KEM the channel was *actually* built on. With key agreement off this
    /// is the static backend regardless of what was selected.
    pub kem: String,
    pub kem_requested: String,
    pub is_pq: bool,
    pub suite: String,
    pub authenticated: bool,
    pub transcript_hash: String,
    pub root_key: String,
    pub plaintext_len: usize,
    pub frames: Vec<FrameView>,

    /// Did the intended recipient actually recover the message? A demo that
    /// only shows what the attacker gets never shows the channel working.
    pub roundtrip_ok: bool,
    pub roundtrip: Option<String>,

    pub verdict: &'static str,
    pub headline: &'static str,
    pub detail: &'static str,
    pub broken: bool,
    pub recovered: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PadRecovery {
    pub recovered: String,
    /// Where recovery stops. Bounded by the crib, and the bound is reported
    /// rather than hidden behind conveniently equal-length messages.
    pub bounded_at: usize,
    pub target_len: usize,
    pub complete: bool,
}

fn suite_of(name: &str) -> aead::Suite {
    match name {
        "chacha" => aead::Suite::ChaCha20Poly1305,
        _ => aead::Suite::Aes256Gcm,
    }
}

/// Split one frame into labelled runs matching the wire format in
/// `transport::obfuscate`: 4 framing bytes, a 4-byte length prefix, the body,
/// then zero padding out to the block.
fn segments(frame: &session::Frame, layers: session::Layers) -> Vec<Segment> {
    let mut out = Vec::new();
    let wire = &frame.wire;

    let body: &[u8] = if layers.transport {
        out.push(Segment { kind: "framing", label: "framing", hex: hex::encode(&wire[..4]) });
        out.push(Segment { kind: "length", label: "length", hex: hex::encode(&wire[4..8]) });
        let len = u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]) as usize;
        &wire[8..8 + len]
    } else {
        wire
    };

    if layers.aead {
        let split = body.len() - aead::TAG_LEN;
        out.push(Segment { kind: "ciphertext", label: "ciphertext", hex: hex::encode(&body[..split]) });
        out.push(Segment { kind: "tag", label: "tag", hex: hex::encode(&body[split..]) });
    } else {
        // No AEAD: this run is the message itself, in the clear.
        out.push(Segment { kind: "plaintext", label: "plaintext", hex: hex::encode(body) });
    }

    if layers.transport {
        let consumed = 8 + body.len();
        if wire.len() > consumed {
            out.push(Segment { kind: "padding", label: "padding", hex: hex::encode(&wire[consumed..]) });
        }
    }
    out
}

fn view(frame: &session::Frame, layers: session::Layers) -> FrameView {
    let body = if layers.transport {
        transport::deobfuscate(&frame.wire).unwrap_or_default()
    } else {
        frame.wire.clone()
    };
    let ciphertext = if layers.aead && body.len() >= aead::TAG_LEN {
        body[..body.len() - aead::TAG_LEN].to_vec()
    } else {
        body
    };

    FrameView {
        wire: hex::encode(&frame.wire),
        wire_len: frame.wire.len(),
        nonce: hex::encode(frame.nonce),
        message_key: hex::encode(frame.message_key),
        counter: frame.counter,
        ciphertext: hex::encode(&ciphertext),
        segments: segments(frame, layers),
    }
}

/// Run one transmission through the configured stack and report what both the
/// intended recipient and the adversary get.
#[wasm_bindgen]
pub fn transmit(config: JsValue) -> Result<JsValue, JsValue> {
    let cfg: Config = serde_wasm_bindgen::from_value(config).map_err(js)?;
    let k = kem::backend(&cfg.backend).map_err(js)?;
    let suite = suite_of(&cfg.suite);

    let layers = session::Layers {
        key_agreement: cfg.key_agreement,
        aead: cfg.aead,
        transport: cfg.transport,
        authenticate: cfg.authenticate,
        ratchet: cfg.ratchet,
        nonce_reuse: cfg.nonce_reuse,
    };

    // With authentication off, the party on the other end is the attacker, and
    // it got there by running a real handshake the victim could not distinguish
    // from the genuine one.
    let (mut sender, mut peer) = if layers.authenticate {
        session::establish(&*k, layers, suite).map_err(js)?
    } else {
        session::establish_mitm(&*k, layers, suite).map_err(js)?
    };

    let f1 = sender.send(layers, cfg.plaintext.as_bytes()).map_err(js)?;
    let f2 = sender.send(layers, cfg.second_message.as_bytes()).map_err(js)?;

    // The peer's decrypt and the attacker's are the same operation when the
    // peer *is* the attacker, so it must not be run twice — the receiving chain
    // advances on every call.
    let (mitm, roundtrip) = if layers.authenticate {
        (None, peer.recv(layers, &f1).ok())
    } else {
        let r = session::adversary_mitm(&mut peer, layers, &f1).map_err(js)?;
        let pt = match &r {
            Recovery::MachineInTheMiddle(p) => Some(p.clone()),
            _ => None,
        };
        (Some(r), pt)
    };

    let passive = session::adversary(&sender, &f1, layers, cfg.adversary_knows_transport).map_err(js)?;

    // Report the cheapest attack that works. A passive observer who already
    // reads the traffic does not need to stand in the middle of it.
    let recovery = match (&passive, mitm) {
        (Recovery::MetadataOnly, Some(active)) => active,
        _ => passive,
    };

    let (verdict, headline, detail, recovered) = match &recovery {
        Recovery::Plaintext(p) => (
            "Plaintext",
            "Plaintext recovered.",
            "The layer that failed was not the one on the outside. Stripping the transport was \
             never the hard part; the key agreement and the AEAD underneath it were doing the \
             work.",
            Some(String::from_utf8_lossy(p).to_string()),
        ),
        Recovery::KeystreamReuse(_) => (
            "KeystreamReuse",
            "Nonce and key both repeated.",
            "One keystream encrypted two messages, so XORing the ciphertexts cancels it. A crib \
             for one message yields the other, as far as the crib reaches.",
            None,
        ),
        Recovery::MachineInTheMiddle(p) => (
            "MachineInTheMiddle",
            "An attacker completed the handshake as the peer.",
            "The signature verified, because it was a valid signature — by the attacker. Without \
             a pinned identity key there is nothing to check it against, and both endpoints \
             report a successful session.",
            Some(String::from_utf8_lossy(p).to_string()),
        ),
        Recovery::MetadataOnly => (
            "MetadataOnly",
            "Length and timing only.",
            "Stripping the transport yields ciphertext, and ciphertext without the session key \
             yields nothing. This is the Kieyoomia result: a fluent speaker with no codebook \
             recognises the language and reads none of it.",
            None,
        ),
    };

    let out = Transmission {
        kem: sender.hs.kem_name.to_string(),
        kem_requested: k.name().to_string(),
        is_pq: sender.hs.kem_is_pq,
        suite: suite.name().to_string(),
        authenticated: sender.hs.authenticated,
        transcript_hash: hex::encode(sender.hs.transcript_hash),
        root_key: hex::encode(sender.hs.root),
        plaintext_len: cfg.plaintext.len(),
        frames: vec![view(&f1, layers), view(&f2, layers)],
        roundtrip_ok: roundtrip.as_deref() == Some(cfg.plaintext.as_bytes()),
        roundtrip: roundtrip.map(|p| String::from_utf8_lossy(&p).to_string()),
        verdict,
        headline,
        detail,
        broken: recovery.is_broken(),
        recovered,
    };
    serde_wasm_bindgen::to_value(&out).map_err(js)
}

/// Recover P2 from two ciphertexts sharing a key and a nonce, given a crib for
/// P1. The page calls this with real ciphertext off the wire rather than
/// printing a sentence about what the attack would do.
#[wasm_bindgen]
pub fn two_time_pad(ct1_hex: &str, ct2_hex: &str, crib: &str) -> Result<JsValue, JsValue> {
    let ct1 = hex::decode(ct1_hex).map_err(js)?;
    let ct2 = hex::decode(ct2_hex).map_err(js)?;
    let target_len = ct2.len();

    let out = session::two_time_pad(&ct1, &ct2, crib.as_bytes());
    let bounded_at = out.len();

    serde_wasm_bindgen::to_value(&PadRecovery {
        recovered: String::from_utf8_lossy(&out).to_string(),
        bounded_at,
        target_len,
        complete: bounded_at >= target_len,
    })
    .map_err(js)
}

/// Which KEM backends this build actually contains. The UI reads this rather
/// than assuming, so a missing feature shows up as absent instead of faked.
#[wasm_bindgen]
pub fn backends() -> Vec<JsValue> {
    ["static", "x25519", "xwing"]
        .iter()
        .filter(|n| kem::backend(n).is_ok())
        .map(|n| JsValue::from_str(n))
        .collect()
}

/// The padding block size, so the page can explain the quantisation it shows
/// instead of hardcoding a number that might drift.
#[wasm_bindgen]
pub fn pad_block() -> usize {
    session::PAD_BLOCK
}
