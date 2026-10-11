# Rust 1.85 platform compatibility

The supported fix for RUSTSEC-2026-0330 and RUSTSEC-2026-0331 is libcrux-kem
0.0.10. Its ML-KEM dependency introduces libcrux-platform 0.0.4. That release
calls three x86 CPUID intrinsics without explicit unsafe blocks, which Rust
1.85 requires. The Mac arm64 build does not compile that module. Actual Linux
PR CI and an independent Rust 1.85 x86 cross-check both reproduced E0133.

`vendor/libcrux-platform-0.0.4` contains the authenticated published crate,
with only those three calls wrapped in unsafe blocks. CPUID is supported on
x86-64; the original leaf bounds and OSXSAVE/XGETBV guards remain unchanged.
The upstream x86 implementation already assumes CPUID availability on x86.
This patch preserves that assumption; it does not broaden architecture support
or change feature detection, entropy, cryptographic operations or secret types.

The archive SHA-256 is
`8bf8bee8c35d34867a3762d6ee7b74e8523a882855c3cfce30484e9554342206`.
The published VCS pin is
`42d68bd49b244b09bd02626c6ffa95e54dc64f91`, path `crates/sys/platform`.
`UPSTREAM.json` retains the original and patched file hashes, archive URL,
source identity and license hash. The Apache license is copied from that exact
upstream revision. No registry-cache source is modified.

Both the root workspace and the separately resolved WASM crate select this
same path patch. All other upstream files remain byte-identical to the archive.
The offline verifier checks the captured manifest and files, rejects unexpected
inputs/symlinks, and reconstructs the original x86 file by reversing exactly the
three changes. Regression controls include tampered, missing and injected inputs.

```sh
node .github/checks/platform-patch.mjs
node --test .github/checks/platform-patch.test.mjs
rustup run 1.85 cargo check --locked -p codetalker-core \
  --no-default-features --features classical,pq \
  --target x86_64-unknown-linux-gnu
```

The existing Linux MSRV build remains required. This patch does not repair the
separate ML-KEM secret-independence integration, establish original compiler
provenance, or prove constant-time behavior. Replace the path patch with a
supported upstream release only after its source changes and all existing
architecture, security, cryptographic and browser checks have been reviewed.
