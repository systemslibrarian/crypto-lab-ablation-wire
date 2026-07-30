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
use codetalker_core::threat;
use codetalker_core::{aead, kem, lab, transport};
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

/// One adversary's standing, straight from `threat::assess`. The page renders
/// these; it does not decide any of them. A threat matrix computed in
/// JavaScript would be exactly the simulation this crate exists to avoid —
/// prose dressed as a result.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdversaryView {
    pub id: String,
    pub label: String,
    pub status: String,
    pub because: String,
}

/// Something the wire gives away whatever the switches say.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeakView {
    pub item: String,
    pub detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Transmission {
    /// The KEM the channel was *actually* built on. With key agreement off this
    /// is the static backend regardless of what was selected.
    pub kem: String,
    pub kem_requested: String,
    pub is_pq: bool,
    /// The signature suite that authenticated the peer, and whether *it* is
    /// post-quantum. A hybrid KEM under a classical signature is post-quantum
    /// for confidentiality only, and the page says so rather than showing one
    /// undifferentiated "PQ" badge.
    pub sig_suite: String,
    pub sig_is_pq: bool,
    pub fully_pq: bool,
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

    /// A1-A5 against this configuration, each with the clause that decided it.
    pub adversaries: Vec<AdversaryView>,
    /// What stays visible on the wire regardless.
    pub metadata: Vec<LeakView>,

    /// Whether the two frames were sealed under different keys and nonces.
    ///
    /// Reported rather than left to the reader, because the alternative is
    /// asking someone to eyeball two 64-character hex strings and decide
    /// whether they match — which is the one comparison the whole ratchet
    /// lesson turns on.
    pub keys_differ: bool,
    pub nonces_differ: bool,
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

    // The sequence itself — who the peer is, which of two attacks to report,
    // whether the round trip succeeded — is `session::exchange`. It used to be
    // written out here, where nothing tested it and where `lab`'s declared
    // outcomes would have had to be checked against a second copy of it.
    let ex = session::exchange(
        &*k,
        layers,
        suite,
        cfg.adversary_knows_transport,
        cfg.plaintext.as_bytes(),
        cfg.second_message.as_bytes(),
    )
    .map_err(js)?;
    let sender = &ex.sender;
    let [f1, f2] = &ex.frames;
    let recovery = &ex.recovery;
    let roundtrip = ex.roundtrip.clone();

    // `verdict` is `Recovery::tag()` and not a literal repeated here, because it
    // is the vocabulary `lab` writes its expectations in and the page compares a
    // reader's prediction against. Two spellings of it would be two things to
    // keep in step.
    let (headline, detail, recovered) = match recovery {
        Recovery::Plaintext(p) => (
            "Plaintext recovered.",
            "The layer that failed was not the one on the outside. Stripping the transport was \
             never the hard part; the key agreement and the AEAD underneath it were doing the \
             work.",
            Some(String::from_utf8_lossy(p).to_string()),
        ),
        Recovery::KeystreamReuse(_) => (
            "Nonce and key both repeated.",
            "One keystream encrypted two messages, so XORing the ciphertexts cancels it. A crib \
             for one message yields the other, as far as the crib reaches.",
            None,
        ),
        Recovery::MachineInTheMiddle(p) => (
            "An attacker completed the handshake as the peer.",
            "The signature verified, because it was a valid signature — by the attacker. Without \
             a pinned identity key there is nothing to check it against, and both endpoints \
             report a successful session.",
            Some(String::from_utf8_lossy(p).to_string()),
        ),
        Recovery::MetadataOnly => (
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
        sig_suite: sender.hs.sig_suite.name().to_string(),
        sig_is_pq: sender.hs.sig_suite.is_pq(),
        fully_pq: sender.hs.is_fully_pq(),
        suite: suite.name().to_string(),
        authenticated: sender.hs.authenticated,
        transcript_hash: hex::encode(sender.hs.transcript_hash),
        root_key: hex::encode(sender.hs.root),
        plaintext_len: cfg.plaintext.len(),
        frames: vec![view(f1, layers), view(f2, layers)],
        roundtrip_ok: roundtrip.as_deref() == Some(cfg.plaintext.as_bytes()),
        roundtrip: roundtrip.map(|p| String::from_utf8_lossy(&p).to_string()),
        verdict: recovery.tag(),
        headline,
        detail,
        broken: recovery.is_broken(),
        recovered,

        adversaries: threat::assess(layers, sender.hs.kem_is_pq)
            .iter()
            .map(|a| AdversaryView {
                id: a.id.to_string(),
                label: a.label.to_string(),
                status: a.status.as_str().to_string(),
                because: a.because.to_string(),
            })
            .collect(),
        metadata: threat::metadata(layers)
            .iter()
            .map(|l| LeakView { item: l.item.to_string(), detail: l.detail.to_string() })
            .collect(),

        keys_differ: f1.message_key != f2.message_key,
        nonces_differ: f1.nonce != f2.nonce,
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

/* --------------------------------------------------------------------- lab */

/// A console state, flattened to the switch ids the page uses. `camelCase`
/// here is `lab::SWITCHES` — the page reads these keys straight onto its own
/// controls, so the two lists agreeing is load-bearing rather than cosmetic.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupView {
    pub key_agreement: bool,
    pub aead: bool,
    pub transport: bool,
    pub authenticate: bool,
    pub ratchet: bool,
    pub nonce_reuse: bool,
    pub adversary_knows_transport: bool,
    /// `None` leaves the reader's selection alone.
    pub kem: Option<String>,
}

fn setup_view(s: &lab::Setup) -> SetupView {
    SetupView {
        key_agreement: s.layers.key_agreement,
        aead: s.layers.aead,
        transport: s.layers.transport,
        authenticate: s.layers.authenticate,
        ratchet: s.layers.ratchet,
        nonce_reuse: s.layers.nonce_reuse,
        adversary_knows_transport: s.adversary_knows_transport,
        kem: s.kem.map(str::to_string),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScenarioView {
    pub id: String,
    pub name: String,
    pub blurb: String,
    pub setup: SetupView,
    pub expect: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepView {
    pub id: String,
    pub title: String,
    pub concept: String,
    pub before: SetupView,
    pub after: SetupView,
    pub instruction: String,
    pub moves: Vec<String>,
    pub question: String,
    pub expect_before: String,
    pub expect_after: String,
    pub explain: String,
    pub adversary: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeView {
    pub tag: String,
    pub label: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Lab {
    pub outcomes: Vec<OutcomeView>,
    pub scenarios: Vec<ScenarioView>,
    pub steps: Vec<StepView>,
    pub switches: Vec<String>,
}

/// The guided sequence and the presets, as data.
///
/// The page renders this; it authors none of it. A lesson written in HTML would
/// be the one panel on the screen that nothing verifies — `tests/ablation.rs`
/// runs every step and every preset through the real channel and asserts the
/// outcome each one declares here.
#[wasm_bindgen]
pub fn lab() -> Result<JsValue, JsValue> {
    let out = Lab {
        outcomes: lab::OUTCOMES
            .iter()
            .map(|o| OutcomeView { tag: o.tag.to_string(), label: o.label.to_string() })
            .collect(),
        scenarios: lab::SCENARIOS
            .iter()
            .map(|s| ScenarioView {
                id: s.id.to_string(),
                name: s.name.to_string(),
                blurb: s.blurb.to_string(),
                setup: setup_view(&s.setup),
                expect: s.expect.to_string(),
            })
            .collect(),
        steps: lab::STEPS
            .iter()
            .map(|s| StepView {
                id: s.id.to_string(),
                title: s.title.to_string(),
                concept: s.concept.to_string(),
                before: setup_view(&s.before),
                after: setup_view(&s.after),
                instruction: s.instruction.to_string(),
                moves: s.moves.iter().map(|m| m.to_string()).collect(),
                question: s.question.to_string(),
                expect_before: s.expect_before.to_string(),
                expect_after: s.expect_after.to_string(),
                explain: s.explain.to_string(),
                adversary: s.adversary.to_string(),
            })
            .collect(),
        switches: lab::SWITCHES.iter().map(|s| s.to_string()).collect(),
    };
    serde_wasm_bindgen::to_value(&out).map_err(js)
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
