#![no_main]
//! Fuzz the only parser in the crate that touches attacker-controlled input.
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
