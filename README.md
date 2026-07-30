# Ablation Wire

The codetalker stack — the 1942 Navajo code-talker stack rebuilt on modern
primitives, with every layer independently switchable. The internal crates are
`codetalker-core` and `codetalker-wasm`, and they keep those names.

The point is not to build a secure channel. It is to let a reader turn layers
off and discover which one was actually load-bearing.

## The claim this crate tests

| 1942 | here | module |
|---|---|---|
| pre-shared codebook | X-Wing KEM → HKDF-SHA256, two-party handshake | `kem`, `handshake`, `kdf` |
| homophonic substitution (A = ant / apple / axe) | AES-256-GCM or ChaCha20-Poly1305 | `aead` |
| rare unwritten language over open radio | padding + framing | `transport` |
| *(absent in 1942)* | peer authentication, transcript-bound | `identity`, `transcript` |
| *(absent in 1942)* | symmetric ratchet | `ratchet` |

Popular retellings credit the third layer. The historical record does not.
Joe Kieyoomia was a fluent Navajo speaker in Japanese custody, made to listen to
intercepts; he recognised his own language and could not read a word of it,
because the codebook was doing the work. See [SOURCES.md](SOURCES.md).

`tests/ablation.rs` encodes that as an assertion:
`kieyoomia_linguist_without_codebook_recovers_nothing`.

## The guided lab

The console opens on a five-experiment sequence rather than on thirty-two layer
combinations and no order to take them in. Each experiment states a starting
state, asks for a prediction, moves one named control, and then explains what
changed and which adversary it defeated or let in.

| # | experiment | change | result | concept |
|---|---|---|---|---|
| 1 | The fluent speaker | give the adversary a fluent speaker | metadata only, unchanged | recognising the language is not holding the codebook |
| 2 | Obscurity on its own | that same adversary, key agreement and AEAD off | full plaintext | a transformed wire is not a confidential one |
| 3 | A valid signature from the wrong peer | peer authentication off | delivered to the attacker | encryption without a pinned identity stops nobody active |
| 4 | One keystream, twice | ratchet already off, repeat the nonce | message 2 from a crib for message 1 | a repeated nonce bites only when the key repeats too |
| 5 | The ratchet earns its place | leave the nonce repeating, ratchet back on | metadata only | nonce uniqueness is a per-key requirement |

The sequence chains deliberately. Experiment 2 keeps the adversary experiment 1
handed a speaker to, so the reader watches the *same* adversary who got nothing a
moment ago read everything — which is a different lesson from watching a fresh
adversary succeed.

All of it lives in `lab.rs` rather than in the page, and that is the point. Every
experiment declares the outcome it expects before and after its change, and
`tests/ablation.rs` runs each one through the real channel and compares. A lesson
authored in HTML could promise a result the crate does not produce and nothing
would notice — in a demo whose whole argument is that the numbers come from the
crate, that would be the one panel on the screen that was merely asserted. The
same tests pin the switches each step names against the actual difference between
its two configurations, and require every prediction offered to be the right
answer somewhere.

The seven presets in the bar are the same data and are asserted the same way.
Any configuration is a link: the address bar carries the switches, the backend,
the AEAD suite, both messages and — in guided mode — the experiment and whether
its result is showing, so `#m=g&s=3&st=r` opens experiment 3 at its debrief.

## Concepts at the point of use

Every switch carries a caption on one schema — what the layer's **job** is, which
**adversary** it answers, what its absence concretely **means**, the **1942**
analogue *and where that analogue stops*, and the **modern** protocol comparison.
Each one ends in a "show me" button that puts the console into the configuration
that demonstrates it.

That button is why the captions live in `explain.rs` and not in the page. A
caption declares the verdict its demonstration produces, and `tests/ablation.rs`
runs it. Two of those assertions are the ones worth having: the transport and
ratchet captions both claim their layer's absence moves *no* verdict, and a test
holds them to it — if either ever started changing the recovery, the captions
would be wrong and the demo would be teaching that every layer announces itself.
The ratchet caption is pinned harder still, because it is the one most likely to
overclaim: a test requires it to deny post-compromise security in as many words
and to distinguish itself from Signal's Double Ratchet.

The layers are deliberately **not** presented as a ladder. Transport
obfuscation, confidentiality, authentication, forward secrecy and post-quantum
resistance are not interchangeable quantities with one of them strongest, and a
reader who leaves believing they are ranked has learned something false from a
demo that switches them on and off in a single column.

Alongside them: a twelve-term glossary, reachable inline on hover *or keyboard
focus* — `:focus` and not `:focus-visible`, so a touch tap works too; a hexdump
legend where focusing a key isolates that field's bytes and says what the field
is for; and the handshake drawn as the sequence that actually ran, which redraws
the far end as the attacker when peer authentication is off. The transcript hash,
root key and per-frame message keys are still there, collapsed behind "inspect
internals" — they are evidence worth keeping and 64 hex characters apiece
competing with the lesson for a novice's attention.

## The handshake is real

`handshake` runs two parties exchanging two messages. Neither function generates
both keypairs — a single `agree()` playing both roles would be a simulation of a
handshake, and this crate's whole claim is that it does not simulate.

```text
Responder                                    Initiator
  (id_sk, id_pk) long-term
  (kem_sk, kem_pk) ephemeral
  sig = Sign(id_sk, H(transcript))
       -- ResponderHello{id_pk, kem_pk, sig} -->
                                  verify sig over H(transcript), pin id_pk
                                  (ss, ct) = Encap(kem_pk)
       <-------- InitiatorReply{ct} ----------
  ss = Decap(kem_sk, ct)

  root = HKDF(ss, "handshake" || H(full transcript))
```

Responder-authenticated, initiator-anonymous — the shape of TLS with server-only
certificates. The transcript hash is signed *and* bound into every AEAD as
associated data, so a frame lifted from another session fails its tag check.

## Layout

```
codetalker-core/
  src/kem.rs         every third-party KEM binding, isolated to one file
  src/handshake.rs   two-party handshake, transcript-bound
  src/identity.rs    Ed25519 peer authentication
  src/transcript.rs  length-prefixed transcript hashing
  src/ratchet.rs     symmetric ratchet (not a Double Ratchet -- see below)
  src/kdf.rs         HKDF-SHA256
  src/aead.rs        AES-256-GCM / ChaCha20-Poly1305
  src/transport.rs   L3 -- deliberately weak, see module docs
  src/session.rs     the ablation harness
  src/threat.rs      which adversary each configuration survives, with reasons
  src/lab.rs         the guided sequence and the presets, as data
  src/explain.rs     the captions: what each layer is for, and the glossary
  tests/kat.rs       published known-answer vectors
  tests/ablation.rs  one test per claim the demo makes in prose
  tests/properties.rs proptest coverage of the untrusted parser
fuzz/                cargo-fuzz targets: transport::deobfuscate, identity::verify
codetalker-wasm/     wasm-bindgen surface
web/index.html       the ablation console
web/pkg/             wasm-pack output, generated, not committed
.github/check-artifact.sh   the Pages artifact resolves without reaching outside itself
```

## Features

| feature | KEM | signatures | notes |
|---|---|---|---|
| `classical` (default) | DHKEM(X25519), RFC 9180 §4.1 | Ed25519, RFC 8032 | not post-quantum; the pre-PQ baseline |
| `pq` | X-Wing (X25519 + ML-KEM-768) | ML-DSA-65, FIPS 204 | post-quantum on **both** halves |

Both halves matters. A hybrid KEM protects confidentiality against a future
quantum adversary — traffic recorded today stays sealed. It does nothing for
authentication, which is a *live* property: a forgery has to happen during the
handshake, not in twenty years. So `pq` with an Ed25519 signature would not be
wrong against adversary A4, but it would invite a reader to assume more than it
delivers. `Handshake::is_fully_pq()` reports the two separately, and the demo
shows them as separate badges rather than one undifferentiated "PQ".

The announced suite is absorbed into the transcript *before* it is signed, so
rewriting that one field to force a downgrade changes the hash and the
signature stops verifying. Algorithm agility without that binding is a
downgrade oracle, not a feature.

`libcrux` was chosen over RustCrypto's `ml-kem` deliberately. The latter ships
with an explicit warning that it has never been independently audited. libcrux
has no independent audit of its PQ implementations either, but the maintainers
have formally verified them using hax and F*, and it is the implementation
shipping in Firefox.

## Build

```sh
cargo test                                   # classical
cargo test --features pq                     # hybrid X-Wing
cargo deny check                             # supply chain
cargo +nightly fuzz run deobfuscate          # the framing parser
cargo +nightly fuzz run identity_verify --features pq   # the signature verifier
wasm-pack build codetalker-wasm --target web --release --out-dir ../web/pkg
.github/check-artifact.sh                    # the Pages artifact resolves
cargo llvm-cov -p codetalker-core --no-default-features --features classical,pq \
  --summary-only                             # coverage; CI floors this at 80%
```

Note the `--out-dir`. The deploy publishes `web/`, so that is where the module
has to land; building into the default `codetalker-wasm/pkg` produces a module
the demo cannot reach. CI uses the same flag for the same reason.

The wasm build carries **two majors of `getrandom`**, and both are load-bearing.
0.2 backs `rand_core` 0.6's `OsRng`, the single entropy source everything funnels
through. 0.4 arrives with RustCrypto 0.11 — `crypto-common` 0.2 depends on it
unconditionally — and refuses to compile for `wasm32-unknown-unknown` without its
`wasm_js` feature, which cannot be requested from a transitive position. Hence the
aliased direct dependency in `codetalker-wasm/Cargo.toml` that exists only to
enable it. If a wasm build ever fails with "the wasm32/64-unknown-unknown are not
supported by default", that dependency is what went missing.

MSRV is 1.85 with `pq` enabled, because libcrux uses edition 2024. The default
feature set builds on considerably older toolchains.

## Known-answer tests

Verified on every CI run, transcribed from the specifications rather than
generated by this crate:

- RFC 5869 test cases 1, 2 and 3 (HKDF-SHA256), PRK and OKM
- **RFC 7748 §5.2 and §6.1 (X25519)** — scalar multiplication and the published
  Diffie-Hellman exchange
- **RFC 8032 §7.1 (Ed25519)** — signatures reproduced byte for byte, and the
  published signatures verified
- RFC 8439 §2.8.2 (ChaCha20-Poly1305)
- NIST GCM test cases 13 and 14 (AES-256-GCM)
- **FIPS 203 (ML-KEM-768)** — 35 ACVP decapsulation vectors
- **FIPS 204 (ML-DSA-65)** — ACVP signature verification, valid *and*
  deliberately invalid cases, because a verifier that accepts everything passes
  a positive-only KAT perfectly
- Exhaustive single-bit tamper rejection across both AEAD suites

The X25519 and Ed25519 vectors close what was the widest gap in this file. The
crate's claim is "real primitives, no simulated math", and until they were
added the two primitives doing the actual key agreement and authentication in
the default build had no published-vector coverage at all — only the symmetric
ones did.

NIST ACVP vectors are **not** vendored; `.github/fetch-vectors.sh` retrieves
them and CI runs it. `tests/kat.rs` **fails loudly** when a file is absent
rather than skipping, because a silently skipped known-answer test reads as a
pass — and it also asserts a minimum number of vectors consumed, because a file
that parses but matches nothing reads as a pass too.

Note the file names in that script. ACVP publishes `prompt.json` (inputs, no
answers) alongside `internalProjection.json` (the answers). CI used to fetch
the former, so even once the file existed there was nothing in it to check
against.

## Honest limitations

**`transport` is deliberately trivial.** It pads and frames; it is not obfs4 and
does not try to be. A convincing obfuscator would undermine the thesis by making
the channel look safe when the layers beneath it are off. Do not lift this
module for anything.

**This is a symmetric ratchet, not a Double Ratchet.** There is no DH ratchet,
so it provides forward secrecy but *not* post-compromise security. Naming it
honestly matters more than naming it impressively.

**Constant-time behaviour does not survive WASM.** The browser JIT makes no
timing guarantees regardless of what this source says. A WASM build is
functionally real and side-channel-wise it is not. Adversary A5 in
[THREAT_MODEL.md](THREAT_MODEL.md) is explicitly out of scope.

**Secret independence is not currently checked, upstream will not allow it.**
There is a `check-secret-independence` feature and a CI job that attempts it,
and the job fails. `libcrux-ml-kem` supports the mode; `libcrux-kem` 0.0.9,
which this crate calls through, does not — with the mode on, libcrux-kem's own
calls stop typechecking because they pass `[u8; 32]` where `Secret<u8>` is now
expected. Upstream code, not fixable here without bypassing libcrux-kem.

The job is kept, failing and non-blocking, because deleting it would hide the
gap. Earlier this was worse than broken: it named a feature on a package that
was not a direct dependency, failed instantly with "does not contain this
feature", and was cited in the threat model as evidence of a check being
performed. It now attempts the real thing and reports the real obstacle.

Consequence worth knowing: **`cargo build --all-features` does not build**, for
exactly this reason. Build the feature sets in the table above instead.

**The two-time-pad recovery is bounded by the crib.** `session::two_time_pad`
recovers exactly as far as the known plaintext reaches, and the test asserts
that bound rather than choosing convenient equal-length messages to hide it.
The demo shows the same bound, rendering the bytes the attack does not reach.

**A repeated nonce is only fatal when the key repeats too.** `nonce_reuse`
pins the nonce, but with the ratchet on every message is sealed under a fresh
key, so the keystreams never coincide and XORing the ciphertexts yields noise.
The harness used to score `nonce_reuse` alone as `KeystreamReuse`, promising a
recovery the arithmetic cannot deliver; it now requires `nonce_reuse &&
!ratchet`. `nonce_reuse_with_a_ratchet_yields_no_pad_at_all` holds that line.
This is the ratchet earning its place rather than decorating the stack.

**Switching key agreement off substitutes the KEM.** `session::establish`
ignores the selected backend when `key_agreement` is false and builds on
`StaticKem` instead, and `adversary` re-derives the message key from that fixed
secret rather than reading it off the frame. Scoring the attack with a key the
attacker was handed would be the simulation this crate exists to avoid.

**A valid signature is not an identity.** Without a pinned peer key, an
attacker's correctly-signed hello verifies fine. Pass `expected_identity`.

## Verification status

Measured on rustc 1.97.1, aarch64-apple-darwin.

| | status |
|---|---|
| `default` (classical) | clean build, 0 warnings, **74/74 tests passing** |
| `--no-default-features --features pq` | **73/73** — the pure post-quantum build |
| `--no-default-features --features classical,pq` | **76/76**, both suites present |
| MSRV, rustc 1.85 | builds `classical,pq` clean |
| FIPS 203 vectors | 35 ML-KEM-768 decapsulation vectors verified |
| FIPS 204 vectors | ML-DSA-65 signature verification, valid and invalid cases |
| `cargo clippy --all-targets` | clean on every feature combination, and on `wasm32` |
| `cargo deny --all-features check` | advisories, bans, licenses, sources — all ok |
| Secret independence | **fails, upstream cannot support it** — see Limitations |
| `cargo audit` | no vulnerabilities; one unmaintained transitive crate, below |
| `wasm-pack build` | 700 KB module, driven end to end across every ablation |
| Threat matrix | A1–A5 computed in `threat.rs`; every row of THREAT_MODEL.md asserted in `tests/ablation.rs` |
| Guided lab | 5 experiments and 7 presets in `lab.rs`; every declared outcome run through the real channel in `tests/ablation.rs` |
| Layer captions | 6 panels in `explain.rs`, each carrying the configuration that demonstrates it; every "show me" asserted to produce the verdict its caption claims |
| Console, in a browser | **63 checks driven headlessly** — the full five-experiment run, prediction scoring, link restore, every preset, reset, every caption's "show me", the glossary, both handshake pictures, and the hexdump keys |
| Deployed demo | **384 configurations driven on the published artifact** — every backend × both suites × all 64 layer combinations, none throwing, no console errors |
| `check-artifact.sh` | every relative reference resolves inside `web/` |
| `cargo fuzz deobfuscate` | 45,027,157 executions, no crashes |
| `cargo fuzz identity_verify` | 577,993 classical + 608,145 with `pq`, no crashes |
| Scheduled fuzzing | nightly, 20 min per target, against a corpus cached between runs — demonstrated: the second run restored 169 seeds and libFuzzer reported them |
| Line coverage | **81.84%** (81.01% region, 72.82% function), floored at 80% in CI |
| Build provenance | the published wasm module is signed; `gh attestation verify` checks it |
| Module size | 740 kB, budgeted at 900 kB by `check-artifact.sh` |
| Actions pinned | every workflow action pinned to a commit SHA, Dependabot moves them |
| `forbid(unsafe_code)` | enforced by the compiler, not asserted in prose |
| RustCrypto 0.11 / dalek 3.0 | migrated; every published vector still reproduces byte for byte |

`cargo audit` reports `proc-macro-error2` as unmaintained (RUSTSEC-2026-0173).
It arrives through `hax-lib-macros` — part of the formal-verification toolchain
that is the reason for choosing libcrux in the first place — and is a
build-time proc-macro that contributes no code to the compiled artifact. Noted
rather than silenced, because the point of running the tool is to read what it
says.

Six things worth knowing about how this got here, because they were all
invisible until something actually ran:

**`--features pq` had never compiled.** `libcrux-kem` takes its RNG through
`rand_core` 0.10's `CryptoRng`; this crate is on 0.6, and the two traits are
unrelated. The old note blamed an outdated toolchain, which was wrong — a
current toolchain fails identically. `kem::os_rng` bridges the two. It was
`kem::libcrux_rng` until x25519-dalek 3.0 moved to `rand_core` 0.10 as well,
at which point the classical KEM needed the identical bridge and the name
stopped describing it.

**The ML-KEM known-answer test verified nothing.** It checked that a file
existed. Worse, CI fetched ACVP's `prompt.json`, which contains inputs and no
expected answers, so there was nothing in the file to check against even in
principle. It now parses `internalProjection.json` and compares real shared
secrets, and fails if it consumes fewer than 30 vectors — a KAT that silently
matches nothing is the same silent pass the loud panic exists to prevent.

**`cargo fuzz` could not have run.** `fuzz/` lived at `codetalker-core/fuzz/`
while both CI and this README invoked it from the repository root, where
cargo-fuzz looks for `./fuzz`. It has been moved to the root and declares its
own `[workspace]`.

**The published page had broken links, and the job meant to catch that was
looking elsewhere.** Pages serves `web/` as the site root, so the footer's
`../README.md` resolved above it and 404ed — while resolving fine in a local
editor preview, which is why it survived. A relative `./README.md` would have
been worse: `web/` has its own README about the directory, so the link would
have silently served the wrong document rather than failing. No favicon was
declared either, leaving a 404 in the console of a page whose argument is that
nothing on it is faked. Meanwhile the `wasm` job built into
`codetalker-wasm/pkg` while `deploy` built into `web/pkg`, so the job
responsible for the browser artifact was validating a build that lands where
the site never reads from. `check-artifact.sh` now resolves every relative
reference against `web/` and both jobs use the same `--out-dir`.

**The fuzzer was documented as covering the only untrusted parser, and there
were two.** `deobfuscate.rs` opened by describing itself that way. But
`handshake::initiate` hands `identity::verify` three slices lifted straight off
the wire -- the claimed identity key, the transcript hash, and the signature --
and they reach `VerifyingKey::from_bytes`, `MLDSA65VerificationKey::new` and
libcrux's ML-DSA verifier. That is the larger surface and the more critical one,
and nothing was fuzzing it. `identity_verify.rs` now does, in two modes: wholly
arbitrary slices, and a genuine key/message/signature triple with one field
mutated in place so lengths stay valid and the verifier reaches its arithmetic
rather than bailing at a length check.

Writing it reproduced the same failure in miniature. The target guarded its
Ed25519 arm with `#[cfg(feature = "classical")]`, but `feature` in a fuzz target
resolves against the *fuzz* crate, which had no such feature -- so the arm
compiled, ran, and did nothing. Only `unexpected_cfgs` caught it. The fuzz crate
now mirrors codetalker-core's feature names so the gate means what it reads as
meaning.

**The fuzzing depth was a sentence, not a fact.** `ci.yml` carried the comment
"Short run on every PR; the corpus grows via scheduled long runs" — and no
scheduled workflow existed anywhere in the repository. `/fuzz/corpus` is
gitignored besides, so nothing persisted between runs even in principle. Every
invocation started from an empty corpus and ran for sixty seconds. The figure in
the table above reads as accumulated depth and was nothing of the kind.

Coverage-guided fuzzing without an accumulating corpus is close to random
testing: the whole mechanism is that inputs reaching new edges get saved and
mutated further. So the sentence was made true rather than deleted —
`fuzz.yml` runs nightly, twenty minutes per target, restoring and saving the
corpus through a rolling cache key and minimising it with `cargo fuzz cmin`
before each save so it does not grow into replay. A fixed cache key would have
been the same bug in a new place: restored once, then frozen.

Demonstrated rather than assumed, by dispatching it twice: the first run started
from nothing and saved, the second restored that cache and entered with 169
seeds, with libFuzzer confirming `seed corpus: files: 169`. A workflow that has
never run is the same category of claim as the sentence it replaced.

## Documents

- [THREAT_MODEL.md](THREAT_MODEL.md) — adversaries A1–A5, and which configurations survive each
- [SECURITY.md](SECURITY.md) — why not to deploy this, and what does count as a vulnerability
- [SOURCES.md](SOURCES.md) — historical citations and specifications implemented
