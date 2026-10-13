# ML-KEM and X-Wing secret-independence patch

## Why this is vendored

The `libcrux-ml-kem` 0.0.11 implementations of the low-level
`libcrux_traits::kem::arrayref::Kem` contract still expose raw `u8` at the
top-level ML-KEM boundary. With `check-secret-independence` enabled, the trait
correctly requires `libcrux_secrets::U8` for randomness, private keys, and
shared secrets. Upstream issue
[`celabshq/libcrux#1356`](https://github.com/celabshq/libcrux/issues/1356)
tracks that incomplete propagation and remains open as of 2026-10-12.

The workspace therefore vendors the exact published `libcrux-ml-kem` 0.0.11,
`libcrux-kem` 0.0.10, and `libcrux-sha3` 0.0.11 archives. All three releases
identify source commit `42d68bd49b244b09bd02626c6ffa95e54dc64f91` and use
Apache-2.0; the license text is at `LICENSE-APACHE`. Each vendor directory's
`UPSTREAM.json` records its crates.io URL, archive SHA-256, VCS path, patch
scope, and modified files. The existing `libcrux-platform` 0.0.4 compatibility
patch remains selected and unchanged.

Unlisted files are preserved byte-for-byte from those crate archives, including
their existing trailing whitespace. Run `git diff --check` against authored and
declared-modified files separately rather than rewriting otherwise-unmodified
upstream sources.

## Patch boundary

The added path is portable and deliberately narrow:

- ML-KEM-512/768/1024 randomness, private-key coefficients, messages, coins,
  implicit-rejection values, equality selector, and shared secrets retain
  `libcrux-secrets` types through SHA-3, centered-binomial sampling,
  polynomial serialization, decapsulation re-encryption, and selection.
- ML-KEM encapsulation keys and ciphertexts are declassified only at their
  specified public output boundary. During decapsulation, only the
  encapsulation-key subsection embedded by the ML-KEM private-key format is
  declassified; it is byte-for-byte the already-public key.
- X-Wing retains classification across SHAKE256 seed expansion, its ML-KEM and
  X25519 inputs and shared secrets, and the SHA3-256 combiner. The released
  `libcrux-curve25519` implementation already treats its HACL call as a trusted
  primitive boundary; this patch does not broaden or rewrite that boundary.
- The released public-byte APIs remain intact. The typed path is checked
  against those APIs for all three ML-KEM parameter sets, valid and rejected
  ciphertexts, and X-Wing.

No job or feature is disabled, no compiler error is suppressed, and no secret
is converted to a public byte merely to satisfy a signature. The portable
path trades optimized SIMD dispatch for a small, auditable verification path;
shipping APIs keep their existing dispatch behavior.

## Validation and limits

Run:

```sh
cargo build -p codetalker-core --features check-secret-independence
cargo test -p codetalker-core --features check-secret-independence \
  --test secret_independence
.github/checks/secret-independence-negative.sh
```

The negative controls require secret-dependent branching, secret indexing, and
crossing into the raw-byte SHA-3 API to fail compilation, while a fixed-control
flow using the typed SHA-3 API must compile. The same check locks actual
declassification to one centralized helper and its four reviewed public-output
call sites; the typed SHA-3 and X-Wing composition contain none.

This is a source-level information-flow check. A green build does not prove
constant-time machine code, validate a particular compiler, or replace timing,
assembly, or side-channel review. The patch must be rebased or removed when an
upstream release resolves #1356; compare archive hashes and rerun the complete
classical, PQ, combined, MSRV, KAT, malformed-input, and browser matrix before
changing any pin.
