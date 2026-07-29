//! Property-based tests.
//!
//! `transport::deobfuscate` is the only function in this crate that parses
//! attacker-controlled bytes. It reads a length field out of untrusted input
//! and slices on it, which is exactly the shape of bug that ships. These
//! properties, plus the fuzz target in `fuzz/`, are why it is not one.

use codetalker_core::{aead, transport};
use proptest::prelude::*;

proptest! {
    /// Obfuscation must be a bijection for anyone who knows the scheme.
    /// That is the point: L3 buys cost, not confidentiality.
    #[test]
    fn obfuscate_roundtrips(data: Vec<u8>, block in 1usize..256) {
        let wire = transport::obfuscate(&data, block);
        prop_assert_eq!(transport::deobfuscate(&wire).unwrap(), data);
    }

    /// The parser must never panic, whatever it is fed.
    #[test]
    fn deobfuscate_never_panics(junk: Vec<u8>) {
        let _ = transport::deobfuscate(&junk);
    }

    /// Not even on input shaped like a valid frame with a hostile length.
    #[test]
    fn deobfuscate_survives_hostile_length(len: u32, body: Vec<u8>) {
        let mut wire = vec![0xAAu8; 4];
        wire.extend_from_slice(&len.to_be_bytes());
        wire.extend_from_slice(&body);
        let _ = transport::deobfuscate(&wire);
    }

    /// Padding must never shrink the wire below the payload.
    #[test]
    fn obfuscation_never_truncates(data: Vec<u8>, block in 1usize..256) {
        let wire = transport::obfuscate(&data, block);
        prop_assert!(wire.len() >= data.len());
    }

    /// AEAD round trip holds for any plaintext and any AAD.
    #[test]
    fn aead_roundtrips(pt: Vec<u8>, aad: Vec<u8>, key: [u8; 32], nonce: [u8; 12]) {
        for suite in [aead::Suite::Aes256Gcm, aead::Suite::ChaCha20Poly1305] {
            let ct = aead::seal(suite, &key, &nonce, &aad, &pt).unwrap();
            prop_assert_eq!(aead::open(suite, &key, &nonce, &aad, &ct).unwrap(), pt.clone());
        }
    }

    /// Any change to the AAD must break authentication.
    #[test]
    fn aead_binds_aad(pt: Vec<u8>, aad: Vec<u8>, key: [u8; 32], nonce: [u8; 12], i in 0usize..64) {
        prop_assume!(!aad.is_empty());
        let ct = aead::seal(aead::Suite::Aes256Gcm, &key, &nonce, &aad, &pt).unwrap();
        let mut bad = aad.clone();
        let idx = i % bad.len();
        bad[idx] ^= 0x01;
        prop_assert!(aead::open(aead::Suite::Aes256Gcm, &key, &nonce, &bad, &ct).is_err());
    }
}
