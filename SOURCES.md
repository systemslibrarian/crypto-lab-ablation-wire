# Sources

This crate names a real person in a test and draws on the history of a living
community. The citations belong in the repository, not in a footer.

## The code talkers

The Navajo code was classified until 1968. Its structure and vocabulary are now
public record.

- **Structure.** Not "speaking Navajo." A Type One Code assigned Navajo words to
  English letters homophonically — the letter A could be sent as the words for
  ant, apple or axe — layered over a codebook of several hundred military terms
  ("iron fish" for submarine, "chicken hawk" for dive bomber).
- **Joe Kieyoomia.** Captured in the Philippines and held as a prisoner of war.
  The Japanese learned Navajo was being used and forced him to listen to
  intercepted transmissions. A native speaker, he recognised the language and
  could not read the traffic, because he did not have the codebook. He was
  tortured in the course of this.
- **Recognition.** The Code Talkers received none for 23 years, owing to the
  classification.
- **Cryptographic assessment.** By modern standards the scheme is a homophonic
  substitution over a rare language. Contemporary analyses hold that a team
  combining a native speaker with trained cryptanalysts would likely have broken
  it. The Japanese had the speaker and never assembled the team — an operational
  failure on their side rather than cryptographic strength on the Allied side.

**Before publishing.** If this demo goes public, contact the Navajo Code Talkers
Museum and the Navajo Nation Museum first. The material is theirs, the framing
should be reviewed by them, and their involvement would be worth more than any
technical feature in this repository.

## Specifications implemented

| Spec | Used for |
|---|---|
| RFC 5869 | HKDF-SHA256 extract-and-expand, and the KAT vectors |
| RFC 9180 §4.1 | DHKEM(X25519) construction |
| RFC 8439 §2.8.2 | ChaCha20-Poly1305 and its KAT vector |
| NIST SP 800-38D | AES-GCM; TC13/TC14 vectors via McGrew & Viega |
| FIPS 203 | ML-KEM-768 |
| FIPS 204 | ML-DSA (planned; not yet wired) |
| draft-connolly-cfrg-xwing-kem | X-Wing hybrid, via `libcrux-kem` |
| RFC 8032 | Ed25519 |

## Known-answer test vectors

RFC 5869, RFC 8439 and NIST GCM vectors are transcribed inline in
`tests/kat.rs` and verified on every CI run.

FIPS 203 ACVP vectors are **not** vendored. `tests/kat.rs` looks for
`tests/vectors/mlkem768.json` and **fails loudly** when it is absent rather than
skipping — a silently skipped known-answer test is worse than none, because it
reads as a pass.
