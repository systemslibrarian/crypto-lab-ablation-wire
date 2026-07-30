# Teaching with Ablation Wire

A guide for running this as a lab, plus a student worksheet and an answer key.

The demo is at
<https://systemslibrarian.github.io/crypto-lab-ablation-wire/>. It needs a
browser and nothing else — no install, no account, no server. Every
configuration is a link, so everything below can be handed out as a URL.

**The assessment question is "why did the result change?", never "what did the
result say?"** A learner who can read a verdict off a screen has demonstrated
that they can read. The whole design of the lab — predict first, move one thing,
watch what moved, explain — exists to make the causal question the natural one.

---

## Learning objectives

After one guided session a learner should be able to answer these without
looking:

1. Which layer protects against which adversary.
2. Why knowing Navajo did not give Joe Kieyoomia the codebook.
3. Why encryption, authentication, and transport obfuscation are different jobs
   rather than three strengths of the same job.
4. Why a valid signature is worth nothing without a pinned identity.
5. Why nonce reuse is catastrophic only when the key repeats with it.
6. What this symmetric ratchet provides, and — more importantly — what it does
   not.
7. Which post-quantum property is being claimed: confidentiality,
   authentication, or both.

### Prerequisites

None, for the guided lab. Learners do not need to have seen a KEM, an AEAD or a
handshake before; every term the page uses is in its own glossary, reachable
inline. What they do need is a willingness to commit to a prediction before
seeing the answer, which is worth saying out loud at the start — the prediction
step is where the learning happens and it is the step people skip.

For the transfer challenges, having completed the five experiments is enough.

---

## Three formats

| Format | Covers | Use when |
|---|---|---|
| **10 minutes** | Experiment 1, then experiment 2 | A lecture segment. The Kieyoomia result followed immediately by the obscurity-only contrast is the entire thesis in two moves. |
| **30 minutes** | All five experiments, with discussion between each | A seminar or lab section. Budget the time for the debriefs, not the clicking. |
| **60 minutes** | Five experiments, both transfer challenges, threat-model debrief | A full lab. The challenges are where you find out whether it transferred. |

### 10-minute version

Open the demo. It starts on experiment 1. Ask the room to predict *before* you
apply the change — a show of hands on the four options is enough, and the split
is itself informative. Apply it, then move straight to experiment 2 and ask the
same question again about the same adversary.

The payoff is the pair, not either half. In experiment 1 an adversary who reads
Navajo fluently gets nothing. In experiment 2 that *same* adversary reads
everything, because the layers underneath were removed. If you only have ten
minutes, that contrast is the thing to spend them on.

### 30-minute version

All five experiments, in order. The sequence is chained deliberately and does
not survive reordering: experiment 2 depends on the adversary keeping the fluent
speaker experiment 1 gave them, and experiment 5 only means anything while the
nonce fault experiment 4 injected is still injected.

Stop after each debrief and ask the diagnostic question from the table below
before moving on.

### 60-minute version

The five experiments, then both transfer challenges, then a threat-model
debrief. For the debrief, put the console in a configuration nobody has seen —
`#m=e&c=111010&sp=0&k=x25519` is a good one — and ask the room to predict all
five adversary rows before revealing the matrix.

---

## The five experiments

Direct links, for handing out or for jumping back to one:

| # | Experiment | Link | The move | Result |
|---|---|---|---|---|
| 1 | The fluent speaker | [`#m=g&s=1`](https://systemslibrarian.github.io/crypto-lab-ablation-wire/#m=g&s=1) | Give the adversary a fluent speaker | Unchanged — metadata only |
| 2 | Obscurity on its own | [`#m=g&s=2`](https://systemslibrarian.github.io/crypto-lab-ablation-wire/#m=g&s=2) | Key agreement and AEAD off | Full plaintext |
| 3 | A valid signature from the wrong peer | [`#m=g&s=3`](https://systemslibrarian.github.io/crypto-lab-ablation-wire/#m=g&s=3) | Peer authentication off | Delivered to the attacker |
| 4 | One keystream, twice | [`#m=g&s=4`](https://systemslibrarian.github.io/crypto-lab-ablation-wire/#m=g&s=4) | Repeat the nonce, ratchet already off | Message 2 from a crib |
| 5 | The ratchet earns its place | [`#m=g&s=5`](https://systemslibrarian.github.io/crypto-lab-ablation-wire/#m=g&s=5) | Ratchet back on, nonce still repeating | Back to metadata only |

Append `&st=r` to any of those to open it at its debrief instead of its
prediction — useful when you are showing a result rather than asking for one.

---

## Expected outcomes for every preset

These are asserted against the crate in `tests/ablation.rs`, so this table
cannot drift from what the demo actually does.

| Preset | Configuration | Verdict | What it is for |
|---|---|---|---|
| Full stack | everything on, ordinary adversary | `MetadataOnly` | The baseline. Establish it before anything else. |
| Kieyoomia test | full stack, adversary has a fluent speaker | `MetadataOnly` | The null result, and the historical claim. |
| Obscurity only | key agreement and AEAD off, transport on, fluent speaker | `Plaintext` | The failure people mistake for the code talkers. |
| MITM succeeds | peer authentication off | `MachineInTheMiddle` | A valid signature by the wrong party. |
| Nonce reuse breaks it | ratchet off, nonce repeated | `KeystreamReuse` | The two-time pad, on real ciphertext. |
| The ratchet earns its place | same fault, ratchet on | `MetadataOnly` | Nonce uniqueness is a per-key requirement. |
| Classical vs post-quantum | full stack, X25519 only | `MetadataOnly` | Nothing on the wire changes. A4 does. |

The last row is the one worth dwelling on. The verdict is identical to the full
stack, the recovered plaintext is identical, the hexdump is the same shape — and
the channel has a completely different future. That is what the threat matrix is
for, and it is the clearest demonstration that a single "is it secure" answer is
not a thing that exists.

---

## Common misconceptions, and what to ask

| Misconception | Diagnostic question | What a correct answer sounds like |
|---|---|---|
| The rarity of Navajo was the security | "The adversary has a fluent speaker. Why does the verdict not move?" | The transport layer was never a secret; the codebook underneath it was. |
| Obscurity is weak encryption | "Is the transport layer a weaker version of AEAD?" | They are different jobs. Padding raises the cost of *classifying* traffic and does nothing to the cost of reading it. |
| Encrypted means safe | "Experiment 3 has key agreement and AEAD both on. Why did the attacker read the message?" | Because they *were* the peer. Confidentiality against an outsider says nothing about who the insider is. |
| A valid signature identifies the peer | "The signature verified. Whose signature was it?" | The attacker's. Validity is not identity; the pin is what makes it a check. |
| Nonce reuse is always fatal | "Experiments 4 and 5 both repeat the nonce. Why does only one break?" | A repeated nonce needs a repeated key. With the ratchet running, two frames share a nonce and nothing else. |
| The ratchet heals a compromise | "An attacker steals the current chain key. What can they read?" | Everything from that point forward. This is a symmetric hash ratchet — forward secrecy, no post-compromise healing. |
| Padding hides the message length | "Transport is on. How long was the message?" | Exactly as long as the frame says at offset 4. Padding quantises the total and then announces the real figure. |
| Post-quantum is one property | "The badge says X-Wing. Are the signatures post-quantum?" | Separate questions with separate deadlines — confidentiality is a recording problem, authentication is a live one. |

The last two are the ones that reliably survive a first pass. Ask them.

---

## Student worksheet

*No spoilers. Hand this out as-is; the answer key is the next section.*

Open <https://systemslibrarian.github.io/crypto-lab-ablation-wire/>.

For each experiment, **write your prediction down before you click Apply.**
Committing in writing is the point — a prediction you did not record is one you
will remember having got right.

### Observation sheet

| # | Experiment | My prediction | What the channel did | Why it changed (one sentence) |
|---|---|---|---|---|
| 1 | The fluent speaker | | | |
| 2 | Obscurity on its own | | | |
| 3 | A valid signature from the wrong peer | | | |
| 4 | One keystream, twice | | | |
| 5 | The ratchet earns its place | | | |

Prediction options, every time:

- Length and timing only
- Message 2, as far as a crib for message 1 reaches
- Delivered and read — by an attacker standing in for the peer
- The full plaintext

### After the five experiments

**Q1.** In experiment 1 the adversary gained an ability and recovered nothing.
In experiment 2 the same adversary recovered everything. What changed, and what
did *not*?

**Q2.** Experiment 3 leaves encryption fully engaged and the attacker still
reads the message. In one sentence, what is authentication for?

**Q3.** Both experiment 4 and experiment 5 repeat the nonce. Why does only one
of them break the channel?

**Q4.** Switch the ratchet off from the full stack. The verdict does not move.
Name the row in the threat matrix that does, and say what it means.

**Q5.** Select X25519 instead of X-Wing on the full stack. Nothing visible
changes. Which adversary's row changed, and why does that adversary not need
access to the wire today?

### Transfer challenges

These have no walkthrough on purpose.

**Hold the line, and know what you gave up.** Configure the channel so that both
a passive observer and an active machine-in-the-middle fail, using classical
primitives only, and deliberately without forward secrecy. Then: two adversaries
still win. Name them and say what each one gets.

**The smallest two-time pad.** Build the smallest configuration in which
repeating the nonce lets an adversary recover message 2 from a crib for message
1. Every switch left on must be necessary. Then: explain why each condition you
kept has to be there — key agreement in particular.

The console checks your configuration against each condition as you work and
tells you which ones you have met.

---

## Answer key

*Instructor copy.*

### The observation sheet

| # | Result | The causal statement to look for |
|---|---|---|
| 1 | Length and timing only | Stripping the transport yields ciphertext; ciphertext without the session key yields nothing. The language was never the secret. |
| 2 | The full plaintext | The adversary gained nothing between 1 and 2 — the *layers underneath the transport* were removed. The wire still looks transformed, which is why obscurity gets mistaken for confidentiality. |
| 3 | Delivered and read, by an attacker standing in for the peer | The signature verified because it was valid; it was the attacker's. With nothing pinned there is nothing to check it against. Note that the passive observer still gets nothing — this break costs the adversary a position on the path. |
| 4 | Message 2, as far as the crib reaches | One keystream over two messages: C₁ ⊕ C₂ = P₁ ⊕ P₂. Nothing was broken cryptographically; a sound construction was used twice. |
| 5 | Length and timing only | The nonce still repeats and no longer matters, because the ratchet hands out a fresh key per message. Nonce uniqueness is a per-key requirement. |

### Questions

**Q1.** The adversary's *capability* did not change — they had the fluent
speaker in both. What changed is that key agreement and AEAD were removed, so
stripping the transport now reaches the message. Full credit requires naming
what stayed the same, not just what changed.

**Q2.** Authentication answers "who is at the other end", which confidentiality
never asks. Accept anything that separates *reading* from *identity*.

**Q3.** Because a repeated nonce only produces a repeated keystream when the key
repeats too. With the ratchet off, one key covers both frames; with it on, the
two frames share a nonce and nothing else. Watch for answers that say "the
ratchet fixes nonce reuse" — it does not fix it, it removes the condition that
makes it matter.

**Q4.** A3, key compromise at time T, moves from defended to exposed. Without a
ratchet one key covers every message, so a single compromise opens the whole
archive rather than one message. The point of the question is that the recovery
verdict cannot show this: it says what an attacker gets *today*.

**Q5.** A4, the future quantum adversary. They do not need access today because
the attack is on a recording — traffic captured now, decrypted whenever the
discrete log falls. This is harvest-now-decrypt-later, and it is the reason
confidentiality and authentication have different post-quantum deadlines: a
forgery has to happen *during* the handshake, so a quantum adversary in 2040
cannot retroactively have been in the middle of one in 2026.

### Transfer challenges

**Hold the line, and know what you gave up.** The configuration is the full
stack with the ratchet off and X25519 selected: A1 defended, A2 defended, KEM
not post-quantum, no forward secrecy.

The two remaining adversaries are A3 and A4, and they fail differently. A3 is a
key compromise at some future time T — with no ratchet, one key covers every
message the session ever sent, so a single compromise opens the archive. A4 needs
no access at all: X25519 traffic recorded today falls whenever the discrete log
does. Neither appears in the verdict, and that is the lesson.

**The smallest two-time pad.** Key agreement on, AEAD on, transport off,
authentication off, ratchet off, nonce repeated.

The instructive part is why key agreement has to stay **on**. Switch it off and
the adversary stops needing the two-time pad — they rebuild the key from a
transcript that crossed the wire in the clear and read both messages outright.
That is a *bigger* break, which makes it a wrong answer to this question rather
than a smaller one. AEAD stays on for the same shape of reason: with nothing
encrypted there is no keystream to reuse. The ratchet must be off, or the frames
share a nonce and nothing else. And authentication must be off — not because it
would prevent the attack, but because it does nothing against it, and a switch
that changes no result is exactly what "smallest" excludes.

That last condition is the one that separates learners who understood
minimality from learners who found a configuration that worked.

---

## Rubric

Grade the causal explanation. Do not grade whether they found a switch
combination — the console will tell them that for free, and rewarding it teaches
them to click rather than think.

| Level | What it looks like |
|---|---|
| **Not yet** | Reports what the screen said. "The verdict was Plaintext." |
| **Developing** | Names the switch that moved. "Plaintext, because AEAD was off." |
| **Proficient** | Names the mechanism. "Plaintext, because with no AEAD the transport layer is only reordering bytes an adversary can put back." |
| **Strong** | Names the mechanism *and* the adversary, and knows what did not change. "The adversary's capability was constant across both experiments; what changed is which layer was underneath the one they could already strip." |

A learner at **Strong** on question 1 has the thesis. A learner at **Strong** on
question 3 or 4 understands that "secure" is not a property a channel has on its
own.

---

## Discussion prompts

### On the limits of the analogy

The demo is built on an analogy and says where it stops; a session that does not
raise this is teaching the analogy rather than the cryptography.

- A modern KEM negotiates a fresh secret per session and forgets it. A codebook
  is a fixed list carried in a satchel and reissued in weeks. Which properties of
  the 1942 system does the analogy genuinely capture, and which are artefacts of
  the modern implementation standing in for it?
- The demo says the codebook was doing the work. Is that too reductive? Operator
  training, message discipline, the pace of combat and the absence of a
  Japanese cryptanalytic team paired with a speaker were all load-bearing in
  1942, and none of them is a layer on this page.
- Contemporary analyses hold that a team pairing a native speaker with trained
  cryptanalysts would likely have broken the code. The Japanese had the speaker
  and never assembled the team. Is that a fact about cryptography or about
  operations — and does the distinction matter to a defender?

### On the historical framing

- Joe Kieyoomia was a prisoner of war and was tortured in the course of being
  made to listen to intercepts. This page uses his experience as evidence for a
  technical claim. What is owed to him in how that is presented?
- Popular retellings credit the rarity of the language. Who benefits from that
  version, and what does it obscure about the work the code talkers actually
  did?
- See [SOURCES.md](SOURCES.md) for citations and the record this framing rests
  on.

---

## Running it offline

The demo is a static page and a WebAssembly module. To serve it from a room with
no internet:

```sh
git clone https://github.com/systemslibrarian/crypto-lab-ablation-wire
cd crypto-lab-ablation-wire
wasm-pack build codetalker-wasm --target web --release --out-dir ../web/pkg
python3 -m http.server -d web 8080
```

Then hand out `http://<your-address>:8080/#m=g&s=1`. Opening the file with
`file://` will not work — ES modules and `WebAssembly.instantiateStreaming` both
need an HTTP origin.
