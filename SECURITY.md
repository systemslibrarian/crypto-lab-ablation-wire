# Security policy

## Do not deploy this

`codetalker-core` is a teaching artifact. It exists so a reader can switch a
layer of a secure channel off and see what an adversary recovers. Several of its
properties are deliberately weak, and one module is weak *on purpose* in a way
that would be a vulnerability anywhere else:

- **`transport` is not an obfuscator.** It pads and frames. It is not obfs4 and
  makes no attempt to be. A convincing obfuscator would undermine the point by
  making the channel look safe while the layers beneath it are switched off.
- **`session::establish` will build a channel with no key agreement at all** if
  you ask it to, substituting a fixed shared secret. That is an ablation, not a
  bug.
- **`nonce_reuse` is a switch.** The crate will happily seal every frame under a
  repeated nonce, because watching that fail is the exercise.
- **The ratchet is symmetric.** Forward secrecy, no post-compromise security.
  See [THREAT_MODEL.md](THREAT_MODEL.md).
- **Constant-time behaviour does not survive WebAssembly**, whatever this source
  says. Adversary A5 is explicitly out of scope.

If you are looking for a library to protect real traffic, use
[rustls](https://github.com/rustls/rustls) or a reviewed implementation of a
reviewed protocol. This crate has had no independent audit, and its dependencies'
post-quantum implementations have not been independently audited either — see
the note on libcrux and hax/F* in the [README](README.md).

## What does count as a vulnerability here

Given the above, the interesting reports are the ones where the crate is
**dishonest** rather than weak — where it claims a property it does not have.
That is the failure mode this repository is organised against. Concretely:

- A configuration the demo scores as **holding** that an adversary can actually
  break.
- A configuration scored as **broken** by an attack the arithmetic cannot
  deliver. (`nonce_reuse` with the ratchet engaged used to be scored this way;
  `nonce_reuse_with_a_ratchet_yields_no_pad_at_all` now holds that line.)
- A panic, out-of-bounds read, or non-termination reachable from
  attacker-controlled bytes — the parsers in `transport::deobfuscate` and
  `identity::verify`. Both are fuzzed; a crashing input is a real finding.
- A known-answer test, CI job, or README claim that passes or reads as passing
  without actually checking the thing it names. Several have been found this
  way already and each is recorded in the README.
- A downgrade: anything that lets attacker-supplied bytes choose a weaker suite
  than both parties agreed to. The announced suite is absorbed into the
  transcript before it is signed specifically to prevent this.

## Reporting

Open a [private security advisory][advisory] on this repository. If you would
rather not use GitHub, a normal issue is fine — given the "do not deploy this"
above, there is no fleet of production users for a public report to endanger, and
the tradeoff that usually justifies embargo does not really apply.

[advisory]: https://github.com/systemslibrarian/crypto-lab-ablation-wire/security/advisories/new

Please include the feature set (`classical`, `pq`, or both) and the layer
configuration, since most behaviour here is configuration-dependent by design.

There is no bounty, and no formal response window. This is a personal project.

## Supported versions

The `main` branch, and only `main`. Nothing is published to crates.io, so there
are no released versions to backport to.

## What is checked, and what is not

The [README's verification section](README.md#verification-status) is the
authoritative list, including the parts that fail. Two worth repeating here:

- **Secret independence is not checked.** The feature and the CI job exist, the
  job attempts the real check, and it fails on upstream code that cannot support
  it. It is kept failing and non-blocking so the gap stays visible rather than
  being deleted.
- **`cargo audit` reports one unmaintained transitive crate**
  (`proc-macro-error2`, RUSTSEC-2026-0173), reached through the
  formal-verification toolchain. It is a build-time proc-macro and contributes
  no code to the compiled artifact. Noted rather than silenced.
