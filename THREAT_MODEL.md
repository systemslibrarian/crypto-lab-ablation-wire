# Threat model

A teaching artifact that does not state its threat model is asking to be
misread. This document says who the adversary is, what they can do, and which
configurations survive them.

## Assets

| Asset | Protected by |
|---|---|
| Message plaintext | AEAD under a per-message key |
| Peer identity | Ed25519 (or ML-DSA) signature over the handshake transcript |
| Past messages after a compromise | Symmetric ratchet |
| Session distinctness | Transcript hash bound as AEAD associated data |

Message **metadata** — length, timing, frequency, the existence of the channel
— is explicitly **not** an asset this design protects. Padding quantises length
and nothing more.

## Adversaries

**A1 — passive network observer.** Reads every byte on the wire, stores it
indefinitely, cannot modify or inject. Defeated by L2 with a real L1.

**A2 — active machine-in-the-middle.** Everything A1 can do, plus modifying,
dropping, replaying and injecting frames, and standing up their own responder.
Defeated by identity authentication *with pinning*. Not defeated by a valid
signature alone — see below.

**A3 — key compromise at time T.** Obtains all key material held at some moment.
The ratchet bounds this to messages from T forward. Without the ratchet, and
with a static key, A3 recovers the entire archive retroactively. This is the
codebook problem, and it is the one the 1942 system actually had.

**A4 — future quantum adversary.** Records traffic now, breaks X25519 later.
Defeated only under `--features pq`, where the X-Wing hybrid holds if *either*
component survives. The default `classical` build does **not** defend against
A4, and says so at runtime through `Kem::is_pq()`.

**A5 — local side-channel observer.** Measures timing or cache behaviour on the
same machine. **Not defended against.** See Limitations.

## What each configuration survives

| Configuration | A1 | A2 | A3 | A4 |
|---|---|---|---|---|
| Full stack, `pq`, pinned | ✅ | ✅ | ✅ | ✅ |
| Full stack, `classical`, pinned | ✅ | ✅ | ✅ | ❌ |
| `authenticate: false` | ✅ | ❌ | ✅ | ❌ |
| `ratchet: false` | ✅ | ✅ | ❌ | ❌ |
| `key_agreement: false` | ❌ | ❌ | ❌ | ❌ |
| `aead: false` (transport only) | ❌ | ❌ | ❌ | ❌ |
| `nonce_reuse: true`, ratchet on | ✅ | ✅ | ✅ | ❌ |
| `nonce_reuse: true`, ratchet off | ❌ | ❌ | ❌ | ❌ |

The last two rows are one claim, split. A repeated nonce is catastrophic only
when the key repeats alongside it: the ratchet derives a fresh message key per
frame, so two frames sharing a nonce still have unrelated keystreams and there
is no pad to exploit. Turn the ratchet off and one key covers every message,
the nonce collision bites, and `session::two_time_pad` recovers plaintext as
far as the crib reaches. Both halves are asserted in `tests/ablation.rs`.

## Two subtleties worth stating explicitly

**A valid signature is not an identity.** `handshake::initiate` accepts an
optional pinned identity key. Without it, an attacker's own well-formed,
correctly-signed hello passes verification — because it *is* correctly signed,
by the attacker. The test
`active_mitm_is_rejected_when_the_peer_is_pinned` exists to keep that
distinction enforced rather than merely documented.

**The signature covers the transcript, not the key.** Signing `kem_pk` alone
would leave the signature replayable into a different session. It signs
`H(transcript)`, so `tampered_kem_key_breaks_the_signed_transcript` fails
closed.

## Out of scope

- Traffic analysis, and any metadata claim beyond length quantisation
- Denial of service
- Endpoint compromise (malware, coerced disclosure, a captured operator)
- Post-compromise security — this is a symmetric ratchet, not a Double Ratchet,
  so there is no DH step to heal from compromise
- Constant-time execution under `wasm32`; see Limitations in the README
