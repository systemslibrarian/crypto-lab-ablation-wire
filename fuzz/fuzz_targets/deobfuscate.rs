#![no_main]
//! Fuzz the framing parser in `transport`.
//!
//! This used to claim it was the only parser touching attacker-controlled
//! input. It never was: `identity::verify` takes three attacker-chosen slices
//! straight off the wire, and is the larger surface of the two. See
//! `identity_verify.rs`.
//!
//! Run: cargo +nightly fuzz run deobfuscate
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must return Ok or Err. Must never panic, and must never read out of bounds.
    if let Ok(out) = codetalker_core::transport::deobfuscate(data) {
        // A successful parse must be internally consistent.
        assert!(out.len() <= data.len());
    }
});
