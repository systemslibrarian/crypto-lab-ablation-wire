//! The teaching assertions.
//!
//! Each test encodes a claim the demo makes in prose. If a claim stops being
//! true, CI says so before a reader does.

use codetalker_core::identity::{Identity, SigSuite};
use codetalker_core::kem::{self, Kem};
use codetalker_core::session::{self, two_time_pad, Layers, Recovery};
use codetalker_core::{aead, handshake, ratchet, transport};

/// The real KEM this build contains. Not hardcoded to x25519: under
/// `--no-default-features --features pq` there is no x25519, and a test suite
/// that assumes one feature set silently stops covering the others.
fn k() -> Box<dyn Kem> {
    kem::backend(KEM_ID).expect("KEM_ID names a backend this build compiled in")
}

#[cfg(feature = "classical")]
const KEM_ID: &str = "x25519";
#[cfg(all(not(feature = "classical"), feature = "pq"))]
const KEM_ID: &str = "xwing";

#[cfg(feature = "classical")]
const KEM_LABEL: &str = "DHKEM(X25519)";
#[cfg(all(not(feature = "classical"), feature = "pq"))]
const KEM_LABEL: &str = "X-Wing (X25519 + ML-KEM-768)";
const SUITE: aead::Suite = aead::Suite::Aes256Gcm;

// ---------------------------------------------------------------------------
// The handshake is real: two parties, two messages, no shortcut.
// ---------------------------------------------------------------------------

#[test]
fn handshake_is_two_party_and_both_sides_agree() {
    let kem = k();
    let responder = handshake::Responder::new(&*kem, Identity::generate()).unwrap();
    let hello = responder.hello();
    let pinned = responder.identity_public();

    let (init, reply) = handshake::initiate(&*kem, &hello, true, Some(&pinned)).unwrap();
    let resp = responder.accept(&reply, true).unwrap();

    assert_eq!(init.root, resp.root, "both sides must derive the same root");
    assert_eq!(init.transcript_hash, resp.transcript_hash);
    assert!(init.authenticated && resp.authenticated);
}

#[test]
fn distinct_sessions_produce_distinct_transcripts() {
    let kem = k();
    let (a, _) = session::establish(&*kem, Layers::default(), SUITE).unwrap();
    let (b, _) = session::establish(&*kem, Layers::default(), SUITE).unwrap();
    assert_ne!(a.hs.transcript_hash, b.hs.transcript_hash);
    assert_ne!(a.hs.root, b.hs.root, "forward secrecy across sessions");
}

#[test]
fn message_survives_the_full_stack_end_to_end() {
    let kem = k();
    let layers = Layers::default();
    let (mut init, mut resp) = session::establish(&*kem, layers, SUITE).unwrap();

    let msg = b"Request immediate air support at grid 214 by 0600.";
    let frame = init.send(layers, msg).unwrap();
    assert_eq!(resp.recv(layers, &frame).unwrap(), msg);
}

// ---------------------------------------------------------------------------
// Authentication. The layer 1942 did not have.
// ---------------------------------------------------------------------------

#[test]
fn active_mitm_is_rejected_when_the_peer_is_pinned() {
    let kem = k();
    let real = handshake::Responder::new(&*kem, Identity::generate()).unwrap();
    let attacker = handshake::Responder::new(&*kem, Identity::generate()).unwrap();

    let pinned = real.identity_public();
    // The attacker's hello carries a perfectly valid signature — under the
    // wrong identity. Signature validity alone is not peer identity.
    let r = handshake::initiate(&*kem, &attacker.hello(), true, Some(&pinned));
    assert!(r.is_err(), "pinned handshake must reject the attacker");
}

#[test]
fn active_mitm_succeeds_when_authentication_is_off() {
    let kem = k();
    let attacker = handshake::Responder::new(&*kem, Identity::generate()).unwrap();

    let (victim, reply) = handshake::initiate(&*kem, &attacker.hello(), false, None).unwrap();
    let attacker_hs = attacker.accept(&reply, false).unwrap();

    // The victim believes it has a channel. It does — with the attacker.
    assert_eq!(victim.root, attacker_hs.root);
    assert!(!victim.authenticated);
}

#[test]
fn tampered_signature_is_rejected() {
    let kem = k();
    let responder = handshake::Responder::new(&*kem, Identity::generate()).unwrap();
    let mut hello = responder.hello();
    let pinned = responder.identity_public();
    hello.signature[0] ^= 0x01;

    assert!(handshake::initiate(&*kem, &hello, true, Some(&pinned)).is_err());
}

#[test]
fn tampered_kem_key_breaks_the_signed_transcript() {
    let kem = k();
    let responder = handshake::Responder::new(&*kem, Identity::generate()).unwrap();
    let mut hello = responder.hello();
    let pinned = responder.identity_public();
    hello.kem_pk.0[0] ^= 0x01;

    // The signature covers the transcript, so swapping the key invalidates it.
    assert!(handshake::initiate(&*kem, &hello, true, Some(&pinned)).is_err());
}

// ---------------------------------------------------------------------------
// The Kieyoomia case, and the layers people mistake for security.
// ---------------------------------------------------------------------------

#[test]
fn kieyoomia_linguist_without_codebook_recovers_nothing() {
    let kem = k();
    let layers = Layers::default();
    let (mut init, _) = session::establish(&*kem, layers, SUITE).unwrap();
    let frame = init.send(layers, b"secret").unwrap();

    // Knowing the transport is exactly the thing that does not help.
    assert_eq!(
        session::adversary(&init, &frame, layers, true).unwrap(),
        Recovery::MetadataOnly
    );
    assert_eq!(
        session::adversary(&init, &frame, layers, false).unwrap(),
        Recovery::MetadataOnly
    );
}

#[test]
fn obscurity_only_is_fully_broken() {
    let kem = k();
    let layers = Layers { key_agreement: false, aead: false, ..Layers::default() };
    let (mut init, _) = session::establish(&*kem, layers, SUITE).unwrap();

    let msg = b"Request immediate air support";
    let frame = init.send(layers, msg).unwrap();
    assert_ne!(&frame.wire[..], &msg[..], "the wire is not the plaintext");

    match session::adversary(&init, &frame, layers, true).unwrap() {
        Recovery::Plaintext(p) => assert_eq!(&p, msg),
        other => panic!("expected full recovery, got {other:?}"),
    }
}

#[test]
fn captured_codebook_opens_everything() {
    let kem = kem::backend("static").unwrap();
    let layers = Layers { key_agreement: false, ..Layers::default() };
    let (mut init, _) = session::establish(&*kem, layers, SUITE).unwrap();

    let msg = b"every message ever sent under this key";
    let frame = init.send(layers, msg).unwrap();
    match session::adversary(&init, &frame, layers, true).unwrap() {
        Recovery::Plaintext(p) => assert_eq!(&p, msg),
        other => panic!("expected full recovery, got {other:?}"),
    }
}

#[test]
fn nonce_reuse_leaks_plaintext_via_xor() {
    let key = [0x99u8; 32];
    let nonce = [7u8; 12];

    let p1 = b"Request immediate air support at grid 214 by 0600.";
    let p2 = b"Enemy armour massing north of the ridge line tonight.";

    let c1 = aead::seal(SUITE, &key, &nonce, b"", p1).unwrap();
    let c2 = aead::seal(SUITE, &key, &nonce, b"", p2).unwrap();

    let recovered = two_time_pad(
        &c1[..c1.len() - aead::TAG_LEN],
        &c2[..c2.len() - aead::TAG_LEN],
        p1,
    );

    // Recovery reaches exactly as far as the crib. That bound is the honest
    // limit of this attack and the test asserts it rather than hiding it.
    let n = recovered.len();
    assert_eq!(n, p1.len().min(p2.len()));
    assert_eq!(&recovered[..], &p2[..n]);
}

// ---------------------------------------------------------------------------
// Ratchet. Forward secrecy, and what its absence costs.
// ---------------------------------------------------------------------------

#[test]
fn ratchet_derives_a_fresh_key_per_message() {
    let mut chain = ratchet::Chain::new([0x55; 32]);
    let k1 = chain.next().unwrap();
    let k2 = chain.next().unwrap();
    let k3 = chain.next().unwrap();

    assert_ne!(k1, k2);
    assert_ne!(k2, k3);
    assert_eq!(chain.n, 3);

    // The chain is the only state: replaying from the same root reproduces it.
    let mut replay = ratchet::Chain::new([0x55; 32]);
    assert_eq!(replay.next().unwrap(), k1);
}

#[test]
fn without_a_ratchet_one_key_covers_every_message() {
    let chain = ratchet::Chain::new([0x77; 32]);
    assert_eq!(chain.static_key().unwrap(), chain.static_key().unwrap());
    assert_eq!(chain.n, 0, "static keying never advances");
}

#[test]
fn ratcheted_frames_use_different_keys_unratcheted_frames_do_not() {
    let kem = k();

    let on = Layers::default();
    let (mut a, _) = session::establish(&*kem, on, SUITE).unwrap();
    let f1 = a.send(on, b"one").unwrap();
    let f2 = a.send(on, b"two").unwrap();
    assert_ne!(f1.message_key, f2.message_key);

    let off = Layers { ratchet: false, ..Layers::default() };
    let (mut b, _) = session::establish(&*kem, off, SUITE).unwrap();
    let g1 = b.send(off, b"one").unwrap();
    let g2 = b.send(off, b"two").unwrap();
    assert_eq!(g1.message_key, g2.message_key);
}

// ---------------------------------------------------------------------------
// Transcript binding.
// ---------------------------------------------------------------------------

#[test]
fn transcript_binding_rejects_cross_session_frames() {
    let kem = k();
    let layers = Layers::default();
    let (mut a, _) = session::establish(&*kem, layers, SUITE).unwrap();
    let (b, _) = session::establish(&*kem, layers, SUITE).unwrap();

    let frame = a.send(layers, b"grid 214").unwrap();
    let body = transport::deobfuscate(&frame.wire).unwrap();

    // Correct key, correct nonce, wrong session. The AAD binding rejects it.
    assert!(aead::open(
        SUITE,
        &frame.message_key,
        &frame.nonce,
        &b.hs.transcript_hash,
        &body
    )
    .is_err());
    // Sanity: with the right transcript it opens.
    assert!(aead::open(
        SUITE,
        &frame.message_key,
        &frame.nonce,
        &a.hs.transcript_hash,
        &body
    )
    .is_ok());
}

// ---------------------------------------------------------------------------
// Transport is not a security boundary, and its parser handles hostile input.
// ---------------------------------------------------------------------------

#[test]
fn transport_roundtrips_and_rejects_garbage() {
    let data = b"ciphertext bytes here";
    let wire = transport::obfuscate(data, 64);
    assert!(wire.len() > data.len());
    assert_eq!(transport::deobfuscate(&wire).unwrap(), data);

    assert!(transport::deobfuscate(b"not a frame").is_err());
    assert!(transport::deobfuscate(&[]).is_err());
    assert!(transport::deobfuscate(&[0xAA, 0xAA, 0xAA, 0xAA, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
}

// ---------------------------------------------------------------------------
// Nonce reuse, through the real channel rather than a hand-built key.
//
// `nonce_reuse_leaks_plaintext_via_xor` above seals twice under a hardcoded
// key, which is the right way to demonstrate the arithmetic and the wrong way
// to test the harness: it cannot see whether the channel repeats the key. These
// two do, and the answer differs depending on the ratchet.
// ---------------------------------------------------------------------------

/// Ciphertext minus its tag — the part a two-time pad operates on.
fn ct_of(frame: &session::Frame) -> Vec<u8> {
    let body = transport::deobfuscate(&frame.wire).unwrap();
    body[..body.len() - aead::TAG_LEN].to_vec()
}

const P1: &[u8] = b"Request immediate air support at grid 214 by 0600.";
const P2: &[u8] = b"Enemy armour massing north of the ridge line tonight.";

#[test]
fn nonce_reuse_without_a_ratchet_is_a_genuine_two_time_pad() {
    let kem = k();
    let layers = Layers { nonce_reuse: true, ratchet: false, ..Layers::default() };
    let (mut a, _) = session::establish(&*kem, layers, SUITE).unwrap();

    let f1 = a.send(layers, P1).unwrap();
    let f2 = a.send(layers, P2).unwrap();
    assert_eq!(f1.nonce, f2.nonce, "the nonce repeats");
    assert_eq!(f1.message_key, f2.message_key, "and so does the key");

    let recovered = two_time_pad(&ct_of(&f1), &ct_of(&f2), P1);
    let n = recovered.len();
    assert_eq!(&recovered[..], &P2[..n], "a crib for P1 yields P2");

    assert!(matches!(
        session::adversary(&a, &f1, layers, true).unwrap(),
        Recovery::KeystreamReuse(_)
    ));
}

#[test]
fn nonce_reuse_with_a_ratchet_yields_no_pad_at_all() {
    let kem = k();
    let layers = Layers { nonce_reuse: true, ..Layers::default() };
    let (mut a, _) = session::establish(&*kem, layers, SUITE).unwrap();

    let f1 = a.send(layers, P1).unwrap();
    let f2 = a.send(layers, P2).unwrap();
    assert_eq!(f1.nonce, f2.nonce, "the nonce still repeats");
    assert_ne!(f1.message_key, f2.message_key, "but the key does not");

    // Two keystreams that were never the same do not cancel. The XOR runs and
    // returns noise, which is exactly why the harness must not call this a
    // break: reporting KeystreamReuse here would promise a recovery that the
    // arithmetic cannot deliver.
    let noise = two_time_pad(&ct_of(&f1), &ct_of(&f2), P1);
    assert_ne!(&noise[..], &P2[..noise.len()]);

    assert_eq!(
        session::adversary(&a, &f1, layers, true).unwrap(),
        Recovery::MetadataOnly,
        "a repeated nonce under a ratchet is survivable"
    );
}

// ---------------------------------------------------------------------------
// The adversary derives its keys; it is never handed them.
// ---------------------------------------------------------------------------

#[test]
fn key_agreement_off_names_the_kem_the_channel_actually_used() {
    let kem = k();
    assert_eq!(kem.name(), KEM_LABEL);

    // Switching key agreement off does not mean "run X25519 and pretend": the
    // channel is rebuilt on a fixed secret, and says so.
    let off = Layers { key_agreement: false, ..Layers::default() };
    let (a, _) = session::establish(&*kem, off, SUITE).unwrap();
    assert_eq!(a.hs.kem_name, "static (captured codebook)");

    let (b, _) = session::establish(&*kem, Layers::default(), SUITE).unwrap();
    assert_eq!(b.hs.kem_name, KEM_LABEL);
}

#[test]
fn captured_codebook_recovery_survives_the_ratchet() {
    // The adversary rebuilds the chain from the fixed secret and walks it to the
    // frame's counter, so recovery holds at message N, not just message one.
    let kem = k();
    let layers = Layers { key_agreement: false, ..Layers::default() };
    let (mut a, _) = session::establish(&*kem, layers, SUITE).unwrap();

    let _ = a.send(layers, b"first").unwrap();
    let _ = a.send(layers, b"second").unwrap();
    let third = a.send(layers, P1).unwrap();
    assert_eq!(third.counter, 3);

    match session::adversary(&a, &third, layers, true).unwrap() {
        Recovery::Plaintext(p) => assert_eq!(&p[..], P1),
        other => panic!("expected full recovery at message 3, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The active attacker. A2 in the threat model, and the one layer 1942 lacked.
// ---------------------------------------------------------------------------

#[test]
fn unauthenticated_channel_is_read_by_the_machine_in_the_middle() {
    let kem = k();
    let layers = Layers { authenticate: false, ..Layers::default() };
    let (mut victim, mut attacker) = session::establish_mitm(&*kem, layers, SUITE).unwrap();

    let frame = victim.send(layers, P1).unwrap();
    match session::adversary_mitm(&mut attacker, layers, &frame).unwrap() {
        Recovery::MachineInTheMiddle(p) => assert_eq!(&p[..], P1),
        other => panic!("expected the attacker to read it, got {other:?}"),
    }

    // A passive observer of the very same frame still gets nothing. The break is
    // the missing authentication, not any weakness in the encryption.
    assert_eq!(
        session::adversary(&victim, &frame, layers, true).unwrap(),
        Recovery::MetadataOnly
    );
}

#[test]
fn pinning_leaves_no_room_for_a_machine_in_the_middle() {
    let kem = k();
    assert!(session::establish_mitm(&*kem, Layers::default(), SUITE).is_err());
    let layers = Layers { authenticate: false, ..Layers::default() };
    let (_, mut attacker) = session::establish_mitm(&*kem, layers, SUITE).unwrap();
    let mut victim = session::establish_mitm(&*kem, layers, SUITE).unwrap().0;
    let frame = victim.send(layers, P1).unwrap();
    assert!(session::adversary_mitm(&mut attacker, Layers::default(), &frame).is_err());
}

// ---------------------------------------------------------------------------
// Signature suite negotiation. Algorithm agility is a downgrade oracle unless
// the negotiated algorithm is bound into what gets signed.
// ---------------------------------------------------------------------------

#[test]
fn announced_signature_suite_is_covered_by_the_signature() {
    let kem = k();
    let responder = handshake::Responder::new(&*kem, Identity::generate()).unwrap();
    let pinned = responder.identity_public();
    let mut hello = responder.hello();

    // Rewrite only the announced suite, leaving key and signature untouched —
    // the shape of a downgrade attempt. The suite is absorbed into the
    // transcript the signature covers, so the hash moves and verification
    // fails closed rather than falling back to something weaker.
    hello.sig_suite = match hello.sig_suite {
        SigSuite::Ed25519 => SigSuite::MlDsa65,
        SigSuite::MlDsa65 => SigSuite::Ed25519,
    };

    assert!(handshake::initiate(&*kem, &hello, true, Some(&pinned)).is_err());
}

#[test]
fn identity_reports_its_suite_and_quantum_resistance_truthfully() {
    let id = Identity::generate();
    let suite = id.suite();

    assert!(
        suite.is_available(),
        "generate() must not name an uncompiled suite"
    );
    assert_eq!(SigSuite::from_name(suite.name()).unwrap(), suite);

    // is_pq is a property of the algorithm, not of the build's ambitions.
    assert_eq!(suite.is_pq(), suite == SigSuite::MlDsa65);
    #[cfg(feature = "pq")]
    assert_eq!(
        suite,
        SigSuite::MlDsa65,
        "a pq build must authenticate with ML-DSA"
    );
    #[cfg(all(not(feature = "pq"), feature = "classical"))]
    assert_eq!(suite, SigSuite::Ed25519);
}

#[test]
fn a_session_is_only_fully_pq_when_both_halves_are() {
    let kem = k();
    let responder = handshake::Responder::new(&*kem, Identity::generate()).unwrap();
    let pinned = responder.identity_public();
    let (hs, _) = handshake::initiate(&*kem, &responder.hello(), true, Some(&pinned)).unwrap();

    // A hybrid KEM under a classical signature is post-quantum for
    // confidentiality and not for authentication. One flag for the session
    // would hide precisely that.
    assert_eq!(hs.is_fully_pq(), hs.kem_is_pq && hs.sig_suite.is_pq());

    #[cfg(all(feature = "pq", not(feature = "classical")))]
    assert!(hs.is_fully_pq(), "a pq-only build should be pq on both halves");
    #[cfg(all(feature = "classical", not(feature = "pq")))]
    assert!(!hs.is_fully_pq(), "a classical build is not post-quantum");
}

// ---------------------------------------------------------------------------
// Feature honesty.
// ---------------------------------------------------------------------------

#[test]
fn pq_backend_reports_honestly_when_absent() {
    let r = kem::backend("xwing");
    #[cfg(feature = "pq")]
    assert!(r.is_ok());
    #[cfg(not(feature = "pq"))]
    assert!(matches!(r, Err(codetalker_core::Error::BackendUnavailable(_))));
}

#[test]
fn kem_reports_its_own_pq_status_truthfully() {
    #[cfg(feature = "classical")]
    assert!(!kem::backend("x25519").unwrap().is_pq());
    assert!(!kem::backend("static").unwrap().is_pq());
    #[cfg(feature = "pq")]
    assert!(kem::backend("xwing").unwrap().is_pq());
}

// ---------------------------------------------------------------------------
// The threat matrix. THREAT_MODEL.md publishes a table of which configuration
// survives which adversary; these assert the code agrees with it, row for row,
// so the document and the module cannot drift apart silently.
// ---------------------------------------------------------------------------

use codetalker_core::threat::{self, Status};

/// Read a row of the published table as (A1, A2, A3, A4).
fn row(layers: Layers, kem_is_pq: bool) -> [Status; 4] {
    let a = threat::assess(layers, kem_is_pq);
    [a[0].status, a[1].status, a[2].status, a[3].status]
}

const D: Status = Status::Defended;
const X: Status = Status::Exposed;

#[test]
fn threat_table_full_stack_pq_survives_every_adversary_in_scope() {
    assert_eq!(row(Layers::default(), true), [D, D, D, D]);
}

#[test]
fn threat_table_full_stack_classical_falls_only_to_the_quantum_adversary() {
    assert_eq!(row(Layers::default(), false), [D, D, D, X]);
}

#[test]
fn threat_table_without_authentication_only_the_active_attacker_wins() {
    let l = Layers { authenticate: false, ..Layers::default() };
    assert_eq!(row(l, true), [D, X, D, D]);
}

#[test]
fn threat_table_without_a_ratchet_key_compromise_opens_the_archive() {
    let l = Layers { ratchet: false, ..Layers::default() };
    assert_eq!(row(l, true), [D, D, X, D]);
}

#[test]
fn threat_table_without_key_agreement_everything_falls() {
    let l = Layers { key_agreement: false, ..Layers::default() };
    assert_eq!(row(l, true), [X, X, X, X]);
}

#[test]
fn threat_table_without_aead_everything_falls() {
    let l = Layers { aead: false, ..Layers::default() };
    assert_eq!(row(l, true), [X, X, X, X]);
}

/// The two halves of the nonce claim, as a threat-model statement this time.
/// The same distinction `nonce_reuse_with_a_ratchet_yields_no_pad_at_all` makes
/// about recovery has to hold here too, or the matrix would contradict the
/// verdict shown beside it.
#[test]
fn threat_table_repeated_nonce_is_survivable_while_the_ratchet_runs() {
    let l = Layers { nonce_reuse: true, ratchet: true, ..Layers::default() };
    assert_eq!(row(l, true), [D, D, D, D]);
}

#[test]
fn threat_table_repeated_nonce_without_a_ratchet_falls_to_everyone() {
    let l = Layers { nonce_reuse: true, ratchet: false, ..Layers::default() };
    assert_eq!(row(l, true), [X, X, X, X]);
}

/// A5 is an admission, not a claim, and must never read as either defended or
/// merely exposed — the crate does not measure it at all.
#[test]
fn side_channel_adversary_is_reported_as_out_of_scope_not_as_defeated() {
    for pq in [true, false] {
        for l in [Layers::default(), Layers { aead: false, ..Layers::default() }] {
            let a = threat::assess(l, pq);
            assert_eq!(a[4].id, "A5");
            assert_eq!(a[4].status, Status::OutOfScope);
        }
    }
}

/// Every judgement has to name the layer responsible. A verdict with an empty
/// or generic clause is the cross-with-no-explanation this module exists to
/// avoid.
#[test]
fn every_adversary_verdict_explains_itself() {
    for pq in [true, false] {
        for mask in 0u8..32 {
            let l = Layers {
                key_agreement: mask & 1 != 0,
                aead: mask & 2 != 0,
                transport: mask & 4 != 0,
                authenticate: mask & 8 != 0,
                ratchet: mask & 16 != 0,
                nonce_reuse: false,
            };
            for a in threat::assess(l, pq) {
                assert!(
                    a.because.len() > 20,
                    "{} has no real reason: {:?}",
                    a.id,
                    a.because
                );
                assert!(!a.id.is_empty() && !a.label.is_empty());
            }
        }
    }
}

/// The transport layer must never be presented as hiding length, because it
/// does not. `obfuscate` pads to a block and then writes the true unpadded
/// length in the clear at offset 4, so the observer gets the exact figure either
/// way — and that is the claim this asserts against the actual bytes.
#[test]
fn padding_does_not_hide_length_because_the_framing_announces_it() {
    let msg = b"exactly nineteen ch";
    let wire = transport::obfuscate(msg, 64);

    // 4 framing bytes + a 4-byte length prefix + the body padded up to the block.
    assert_eq!(
        wire.len(),
        8 + 64,
        "19 bytes pads to one 64-byte block behind an 8-byte header"
    );

    let announced = u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]) as usize;
    assert_eq!(
        announced,
        msg.len(),
        "the framing states the exact unpadded length, so padding quantises nothing"
    );

    let leaks = threat::metadata(Layers::default());
    assert!(
        leaks.iter().any(|l| l.item == "exact message length"),
        "the metadata summary must say the length is exposed"
    );
    assert!(
        leaks.iter().any(|l| l.item == "frame structure"),
        "the 0xAA marker is a fingerprint and must be listed"
    );
}

#[test]
fn metadata_always_admits_that_the_channel_and_its_timing_are_visible() {
    for transport_on in [true, false] {
        let l = Layers { transport: transport_on, ..Layers::default() };
        let leaks = threat::metadata(l);
        assert!(leaks.iter().any(|x| x.item == "channel exists"));
        assert!(leaks.iter().any(|x| x.item == "timing and frequency"));
        assert!(leaks.iter().any(|x| x.item == "exact message length"));
        for x in &leaks {
            assert!(x.detail.len() > 20, "{} needs a real explanation", x.item);
        }
    }
}
