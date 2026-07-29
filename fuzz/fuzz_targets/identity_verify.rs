#![no_main]
//! Fuzz the signature verifier, the crate's *other* untrusted parser.
//!
//! `deobfuscate` was described for a while as the only parser touching
//! attacker-controlled input. It is not. In `handshake::initiate` the responder's
//! hello arrives from the wire and every field of it is attacker-chosen:
//!
//! ```text
//! identity::verify(suite, &hello.identity_pk, &transcript_hash, &hello.signature)
//! ```
//!
//! All three byte slices are supplied by whoever sent the frame. They reach
//! `VerifyingKey::from_bytes`, `MLDSA65VerificationKey::new` and libcrux's
//! ML-DSA verifier. That is a larger and considerably more security-critical
//! surface than the length-prefixed framing in `transport`, and it was the one
//! not being fuzzed.
//!
//! Run: cargo +nightly fuzz run identity_verify
//!      cargo +nightly fuzz run identity_verify --features pq   # adds ML-DSA-65
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

use codetalker_core::identity::{self, Identity, SigSuite};

/// A genuine keypair and a genuine signature over a known message.
///
/// Built once. The point of mode 1 below is to reach the verifier's arithmetic,
/// and arithmetic is only reachable behind the length checks -- so the fuzzer
/// needs correctly-sized inputs to mutate rather than random slices that are
/// rejected on the first `try_into`.
struct Valid {
    suite: SigSuite,
    public: Vec<u8>,
    msg: Vec<u8>,
    sig: Vec<u8>,
}

fn ed25519() -> Option<&'static Valid> {
    static V: OnceLock<Option<Valid>> = OnceLock::new();
    V.get_or_init(|| {
        if !SigSuite::Ed25519.is_available() {
            return None;
        }
        // Deterministic, so a crash found here reproduces from the input alone
        // rather than depending on whatever the RNG happened to produce.
        #[cfg(feature = "classical")]
        {
            let id = Identity::from_ed25519_seed([7u8; 32]);
            let msg = b"transcript hash stand-in".to_vec();
            let sig = id.sign(&msg).expect("ed25519 signing is infallible");
            Some(Valid { suite: SigSuite::Ed25519, public: id.public(), msg, sig })
        }
        #[cfg(not(feature = "classical"))]
        None
    })
    .as_ref()
}

fn mldsa65() -> Option<&'static Valid> {
    static V: OnceLock<Option<Valid>> = OnceLock::new();
    V.get_or_init(|| {
        if !SigSuite::MlDsa65.is_available() {
            return None;
        }
        let id = Identity::generate_with(SigSuite::MlDsa65).ok()?;
        let msg = b"transcript hash stand-in".to_vec();
        let sig = id.sign(&msg).ok()?;
        Some(Valid { suite: SigSuite::MlDsa65, public: id.public(), msg, sig })
    })
    .as_ref()
}

/// Overwrite a window of `base` with `patch`, starting at a fuzzer-chosen
/// offset. Length is preserved, which is the whole reason for doing it this way.
fn splice(base: &[u8], patch: &[u8], offset: usize) -> Vec<u8> {
    let mut out = base.to_vec();
    if out.is_empty() || patch.is_empty() {
        return out;
    }
    let start = offset % out.len();
    for (i, b) in patch.iter().enumerate() {
        if start + i >= out.len() {
            break;
        }
        out[start + i] = *b;
    }
    out
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let (control, body) = (&data[..3], &data[3..]);
    let suites: &[SigSuite] = &[SigSuite::Ed25519, SigSuite::MlDsa65];
    let suite = suites[(control[0] >> 1) as usize % suites.len()];

    if control[0] & 1 == 0 {
        // Mode 0 -- wholly arbitrary input. Three slices carved at fuzzer-chosen
        // split points. Must return Ok or Err; must never panic, and must never
        // accept, because the fuzzer is not going to forge a signature.
        let n = body.len();
        if n == 0 {
            return;
        }
        let a = (control[1] as usize * n) / 256;
        let b = a + ((control[2] as usize * (n - a)) / 256);
        let (public, msg, sig) = (&body[..a], &body[a..b], &body[b..]);

        // A suite this build was not compiled with must refuse rather than
        // silently fall through to another one.
        let got = identity::verify(suite, public, msg, sig);
        if !suite.is_available() {
            assert!(got.is_err(), "unavailable suite {:?} must not verify", suite);
        }
        assert!(
            got.is_err(),
            "verifier accepted attacker-chosen bytes: suite={:?} pk={} msg={} sig={}",
            suite,
            public.len(),
            msg.len(),
            sig.len()
        );
    } else {
        // Mode 1 -- near-valid input. Real key, real message, real signature,
        // with one of the three fields mutated in place so lengths stay correct
        // and the verifier runs its arithmetic instead of bailing on a length
        // check. This is where a verifier that accepts a tampered signature
        // would show up, which is the failure that actually matters.
        let Some(v) = (match suite {
            SigSuite::Ed25519 => ed25519(),
            SigSuite::MlDsa65 => mldsa65(),
        }) else {
            return;
        };

        let offset = control[2] as usize;
        let (public, msg, sig) = match control[1] % 3 {
            0 => (splice(&v.public, body, offset), v.msg.clone(), v.sig.clone()),
            1 => (v.public.clone(), splice(&v.msg, body, offset), v.sig.clone()),
            _ => (v.public.clone(), v.msg.clone(), splice(&v.sig, body, offset)),
        };

        let tampered = public != v.public || msg != v.msg || sig != v.sig;
        let got = identity::verify(v.suite, &public, &msg, &sig);

        if tampered {
            // Guarded on `tampered`: the fuzzer can legitimately splice the
            // original bytes back over themselves, and a verifier that rejected
            // *that* would be the broken one.
            assert!(
                got.is_err(),
                "verifier accepted a tampered {:?} triple",
                v.suite
            );
        } else {
            assert!(got.is_ok(), "verifier rejected a genuine {:?} triple", v.suite);
        }
    }
});
