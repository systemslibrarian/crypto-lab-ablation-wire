//! The guided sequence: five experiments, and the scenarios they move between.
//!
//! The console shows every switch at once, which is right for exploring and
//! wrong for learning. A reader arriving cold has thirty-two layer combinations,
//! no order to take them in, and no way to tell whether a change they just made
//! was supposed to matter. This module supplies the order: a short chain of
//! experiments that each move one thing, declare what the channel will do, and
//! then say why.
//!
//! The curriculum is data in the crate rather than prose in the page, and that
//! is the whole design. Every [`Step`] states the outcome it expects both before
//! and after its change, and `tests/ablation.rs` runs each one through
//! [`session::exchange`](crate::session::exchange) and compares. A guided lab
//! written in HTML could promise a result the crate does not produce and nothing
//! would notice — which in a demo whose argument is *the numbers come from the
//! crate* would be the one panel on the screen that was merely asserted.
//!
//! Two consequences worth stating, because they are constraints and not
//! accidents:
//!
//! - [`Step::moves`] names the switches a step asks the reader to change, and a
//!   test compares it against [`Setup::diff`]. The instruction and the
//!   configuration cannot drift apart.
//! - [`OUTCOMES`] is the list of predictions offered, and a test requires each
//!   one to be the right answer to some step. An option that is never correct
//!   teaches readers to stop reading the options.

use crate::session::Layers;

/// A complete console state: the switches, what the adversary is assumed to
/// know, and the KEM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setup {
    pub layers: Layers,
    /// The Kieyoomia switch — the adversary has a fluent speaker and can strip
    /// the transport layer.
    pub adversary_knows_transport: bool,
    /// Pinned only where the scenario is *about* the backend. `None` leaves
    /// whatever the reader selected, because no other outcome here depends on
    /// the KEM — and pinning one anyway would quietly teach that it does.
    pub kem: Option<&'static str>,
}

/// The console's switch identifiers, in rail order.
///
/// These are the ids the browser uses, which is an odd thing for a crypto crate
/// to know. It holds them because the alternative is worse: the page would map
/// [`Setup::diff`] onto its own controls by hand, and a renamed switch would
/// silently highlight nothing during the one beat of the lesson where the reader
/// is being told where to look.
pub const SWITCHES: [&str; 7] = [
    "keyAgreement",
    "aead",
    "transport",
    "authenticate",
    "ratchet",
    "nonceReuse",
    "adversaryKnowsTransport",
];

impl Setup {
    /// The switches that differ, named as the console names them.
    pub fn diff(&self, other: &Setup) -> Vec<&'static str> {
        let (a, b) = (self.layers, other.layers);
        let pairs: [(&'static str, bool); 7] = [
            ("keyAgreement", a.key_agreement != b.key_agreement),
            ("aead", a.aead != b.aead),
            ("transport", a.transport != b.transport),
            ("authenticate", a.authenticate != b.authenticate),
            ("ratchet", a.ratchet != b.ratchet),
            ("nonceReuse", a.nonce_reuse != b.nonce_reuse),
            (
                "adversaryKnowsTransport",
                self.adversary_knows_transport != other.adversary_knows_transport,
            ),
        ];
        pairs.iter().filter(|(_, d)| *d).map(|(k, _)| *k).collect()
    }
}

// Builders rather than a seven-argument constructor: `speaker(no_aead(full()))`
// reads as the configuration it describes, and a positional call would not.
//
// These read as 0% in `cargo llvm-cov` and that is not a gap to fill. They run
// during const evaluation to build `SCENARIOS` and `STEPS`, which the coverage
// instrumentation does not trace; the values they produce are then exercised end
// to end by every test below. Writing runtime callers to colour the report green
// would buy a number and no confidence.
//
// `pub(crate)` because `explain` builds its demonstration configurations the same
// way, and two sets of builders for one type is one set too many.
pub(crate) const fn full() -> Setup {
    Setup {
        layers: Layers {
            key_agreement: true,
            aead: true,
            transport: true,
            authenticate: true,
            ratchet: true,
            nonce_reuse: false,
        },
        adversary_knows_transport: false,
        kem: None,
    }
}

pub(crate) const fn speaker(mut s: Setup) -> Setup {
    s.adversary_knows_transport = true;
    s
}
pub(crate) const fn no_key_agreement(mut s: Setup) -> Setup {
    s.layers.key_agreement = false;
    s
}
pub(crate) const fn no_aead(mut s: Setup) -> Setup {
    s.layers.aead = false;
    s
}
pub(crate) const fn no_auth(mut s: Setup) -> Setup {
    s.layers.authenticate = false;
    s
}
pub(crate) const fn no_ratchet(mut s: Setup) -> Setup {
    s.layers.ratchet = false;
    s
}
pub(crate) const fn repeat_nonce(mut s: Setup) -> Setup {
    s.layers.nonce_reuse = true;
    s
}
pub(crate) const fn pre_quantum(mut s: Setup) -> Setup {
    s.kem = Some("x25519");
    s
}

/// One prediction a reader can make before a change is applied.
#[derive(Debug, Clone, Copy)]
pub struct Outcome {
    /// Matches [`Recovery::tag`](crate::session::Recovery::tag).
    pub tag: &'static str,
    pub label: &'static str,
}

/// The predictions offered, in increasing order of how much the adversary gets.
///
/// Every one of these is the correct answer to at least one [`STEPS`] entry, and
/// a test enforces it. A distractor that is never right is worse than no
/// distractor: it is a lesson in ignoring the list.
pub const OUTCOMES: [Outcome; 4] = [
    Outcome { tag: "MetadataOnly", label: "Length and timing only" },
    Outcome {
        tag: "KeystreamReuse",
        label: "Message 2, as far as a crib for message 1 reaches",
    },
    Outcome {
        tag: "MachineInTheMiddle",
        label: "Delivered and read — by an attacker standing in for the peer",
    },
    Outcome { tag: "Plaintext", label: "The full plaintext" },
];

/// A named configuration a reader can jump straight to.
#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    pub id: &'static str,
    pub name: &'static str,
    pub blurb: &'static str,
    pub setup: Setup,
    /// The outcome this scenario exists to show. Asserted, not advertised.
    pub expect: &'static str,
}

/// One experiment: a starting state, one change, and a debrief.
#[derive(Debug, Clone, Copy)]
pub struct Step {
    pub id: &'static str,
    pub title: &'static str,
    /// The idea the step is for, in one line.
    pub concept: &'static str,
    pub before: Setup,
    pub after: Setup,
    /// The switches to move, as an instruction to the reader.
    pub instruction: &'static str,
    /// The same instruction as switch ids, so the page can highlight exactly the
    /// controls named. Asserted equal to `before.diff(&after)`.
    pub moves: &'static [&'static str],
    pub question: &'static str,
    /// What the channel does in `before` — shown, because a step whose result is
    /// "unchanged" needs a starting result to be unchanged *from*.
    pub expect_before: &'static str,
    pub expect_after: &'static str,
    /// The causal debrief. Two sentences: what happened, and why.
    pub explain: &'static str,
    /// The adversary this step defeats or enables, by their `THREAT_MODEL.md`
    /// identifier. A result with no adversary attached is not a security result.
    pub adversary: &'static str,
}

pub const SCENARIOS: [Scenario; 7] = [
    Scenario {
        id: "full-stack",
        name: "Full stack",
        blurb: "Every layer engaged, and an adversary with no advantages.",
        setup: full(),
        expect: "MetadataOnly",
    },
    Scenario {
        id: "kieyoomia",
        name: "Kieyoomia test",
        blurb: "The adversary reads the language fluently. It changes nothing.",
        setup: speaker(full()),
        expect: "MetadataOnly",
    },
    Scenario {
        id: "obscurity-only",
        name: "Obscurity only",
        blurb: "Transport dressing over a plaintext, against someone who knows the scheme.",
        setup: speaker(no_aead(no_key_agreement(full()))),
        expect: "Plaintext",
    },
    Scenario {
        id: "mitm",
        name: "MITM succeeds",
        blurb: "Strong encryption, no pinned identity, and the attacker is the peer.",
        setup: speaker(no_auth(full())),
        expect: "MachineInTheMiddle",
    },
    Scenario {
        id: "two-time-pad",
        name: "Nonce reuse breaks it",
        blurb: "One key, one nonce, two messages — and a crib recovers the second.",
        setup: speaker(repeat_nonce(no_ratchet(full()))),
        expect: "KeystreamReuse",
    },
    Scenario {
        id: "ratchet-saves-it",
        name: "The ratchet earns its place",
        blurb: "The same repeated nonce, now under a key that changes every message.",
        setup: speaker(repeat_nonce(full())),
        expect: "MetadataOnly",
    },
    Scenario {
        id: "pre-quantum",
        name: "Classical vs post-quantum",
        blurb: "X25519 alone. Nothing on the wire changes; A4 does.",
        setup: pre_quantum(full()),
        expect: "MetadataOnly",
    },
];

/// The five experiments, in the order they build on each other.
///
/// The chain matters. Experiment 1 hands the adversary a fluent speaker and
/// nothing happens; experiment 2 leaves that speaker in place and removes the
/// layers underneath, so the *same* adversary who got nothing a moment ago reads
/// everything. Running experiment 2 against a fresh adversary would still show
/// plaintext and would show it for the wrong reason.
pub const STEPS: [Step; 5] = [
    Step {
        id: "kieyoomia",
        title: "The fluent speaker",
        concept: "Recognising the language is not possession of the codebook.",
        before: full(),
        after: speaker(full()),
        instruction: "Give the adversary a fluent speaker.",
        moves: &["adversaryKnowsTransport"],
        question: "The adversary can now strip the transport layer. What do they recover?",
        expect_before: "MetadataOnly",
        expect_after: "MetadataOnly",
        explain: "Stripping the transport yields ciphertext, and ciphertext without the session \
                  key yields nothing. This is the result Joe Kieyoomia produced under \
                  interrogation: he could hear his own language and could not read a word of the \
                  traffic, because the codebook was the layer doing the work.",
        adversary: "A1 stays defended",
    },
    Step {
        id: "obscurity-only",
        title: "Obscurity on its own",
        concept: "A transformed wire is not a confidential one.",
        before: speaker(full()),
        after: speaker(no_aead(no_key_agreement(full()))),
        instruction: "Switch off key agreement and authenticated encryption. Leave the transport \
                      layer on.",
        moves: &["keyAgreement", "aead"],
        question: "The wire is still framed and padded. What does the same adversary recover now?",
        expect_before: "MetadataOnly",
        expect_after: "Plaintext",
        explain: "The adversary did not gain a capability — they had the speaker a moment ago and \
                  got nothing. What changed is that the layers beneath the transport are gone, so \
                  stripping it now reaches the message itself. The wire still looks transformed, \
                  which is exactly why obscurity is mistaken for confidentiality.",
        adversary: "A1 exposed",
    },
    Step {
        id: "mitm",
        title: "A valid signature from the wrong peer",
        concept: "Encryption without a pinned identity does not stop an active attacker.",
        before: speaker(full()),
        after: speaker(no_auth(full())),
        instruction: "Switch off peer authentication.",
        moves: &["authenticate"],
        question: "Encryption and key agreement are both back on. What does the adversary get?",
        expect_before: "MetadataOnly",
        expect_after: "MachineInTheMiddle",
        explain: "The handshake succeeded and the signature verified — it was a valid signature, \
                  by the attacker. With no pinned identity key there is nothing to check it \
                  against, so both endpoints report a good session and the attacker is one of \
                  them. Note that the passive observer still gets nothing; this break costs the \
                  adversary a position on the path.",
        adversary: "A2 exposed",
    },
    Step {
        id: "two-time-pad",
        title: "One keystream, twice",
        concept: "A repeated nonce is catastrophic only when the key repeats with it.",
        before: speaker(no_ratchet(full())),
        after: speaker(repeat_nonce(no_ratchet(full()))),
        instruction: "With the ratchet already off, repeat the nonce.",
        moves: &["nonceReuse"],
        question: "Both frames are now sealed under one key and one nonce. What follows?",
        expect_before: "MetadataOnly",
        expect_after: "KeystreamReuse",
        explain: "Two ciphertexts under one keystream cancel it: C1 XOR C2 is P1 XOR P2, so a crib \
                  for message 1 yields message 2 for as far as the crib reaches. Nothing was \
                  broken cryptographically — the construction is sound and was used twice.",
        adversary: "A1 exposed",
    },
    Step {
        id: "ratchet-saves-it",
        title: "The ratchet earns its place",
        concept: "Nonce uniqueness is a per-key requirement, not a global one.",
        before: speaker(repeat_nonce(no_ratchet(full()))),
        after: speaker(repeat_nonce(full())),
        instruction: "Leave the nonce repeating. Switch the ratchet back on.",
        moves: &["ratchet"],
        question: "The fault is still injected. Does the recovery survive it?",
        expect_before: "KeystreamReuse",
        expect_after: "MetadataOnly",
        explain: "The nonce still repeats and it no longer matters, because the ratchet hands out \
                  a fresh key per message and the two frames now share a nonce and nothing else. \
                  Read the consequence off the frame comparison rather than the switch: it is \
                  key 1 versus key 2 that decides this.",
        adversary: "A1 defended, A3 defended",
    },
];

// ---------------------------------------------------------------------------
// Transfer challenges: a goal, not a recipe.
// ---------------------------------------------------------------------------

/// One condition a challenge configuration has to meet.
///
/// Data rather than a closure, because the page has to *render* the checklist —
/// a reader working on a goal needs to see which conditions they have already
/// met and which they have not, and a boolean-returning function can only tell
/// them they are wrong.
#[derive(Debug, Clone, Copy)]
pub enum Requirement {
    /// A named adversary must end up in this status.
    Adversary {
        id: &'static str,
        status: &'static str,
        label: &'static str,
    },
    /// The KEM *in force* must (or must not) be post-quantum.
    PostQuantum { yes: bool, label: &'static str },
    /// A console switch must be in this position.
    Switch {
        id: &'static str,
        on: bool,
        label: &'static str,
    },
    /// The recovery verdict, by [`Recovery::tag`](crate::session::Recovery::tag).
    Verdict { tag: &'static str, label: &'static str },
    /// Every switch left on must be load-bearing: turning any one of them off
    /// has to change the verdict. This is what makes "the smallest
    /// configuration" a checkable claim rather than a matter of opinion.
    Minimal { label: &'static str },
}

impl Requirement {
    pub fn label(&self) -> &'static str {
        match self {
            Requirement::Adversary { label, .. }
            | Requirement::PostQuantum { label, .. }
            | Requirement::Switch { label, .. }
            | Requirement::Verdict { label, .. }
            | Requirement::Minimal { label } => label,
        }
    }
}

/// A task stated as an outcome, with the reasoning left to the reader.
///
/// The five experiments test whether someone can follow a tour. These test
/// whether they can build a configuration nobody showed them, which is a
/// different and harder thing — and the one that says whether the model
/// transferred.
#[derive(Debug, Clone, Copy)]
pub struct Challenge {
    pub id: &'static str,
    pub title: &'static str,
    pub brief: &'static str,
    pub requirements: &'static [Requirement],
    /// Asked once the configuration validates. Configuring it is half the task;
    /// this is the half that distinguishes understanding from switch-flipping.
    pub question: &'static str,
    /// What a correct answer says, revealed for self-checking. Free text cannot
    /// be graded here and pretending otherwise would be worse than not trying.
    pub answer: &'static str,
    /// A configuration meeting every requirement. Asserted, so a challenge
    /// cannot ship unsolvable.
    pub solution: Setup,
    /// A KEM backend this challenge cannot be attempted without.
    ///
    /// Only set where the task is *about* the KEM. A build compiled
    /// `--no-default-features --features pq` has no classical backend at all, so
    /// "use classical primitives only" is not a hard task there, it is an
    /// impossible one — and a console that offers an unsolvable goal teaches a
    /// reader to distrust the checklist.
    pub needs_backend: Option<&'static str>,
}

pub const CHALLENGES: [Challenge; 2] = [
    Challenge {
        id: "hold-the-line",
        title: "Hold the line, and know what you gave up",
        brief: "Configure the channel so that both a passive observer and an active \
                machine-in-the-middle fail, using classical primitives only, and \
                deliberately without forward secrecy.",
        requirements: &[
            Requirement::Adversary {
                id: "A1",
                status: "defended",
                label: "A passive observer recovers nothing",
            },
            Requirement::Adversary {
                id: "A2",
                status: "defended",
                label: "An active attacker cannot become the peer",
            },
            Requirement::PostQuantum {
                yes: false,
                label: "Classical primitives only — the KEM in force is not post-quantum",
            },
            Requirement::Switch {
                id: "ratchet",
                on: false,
                label: "No forward secrecy — the ratchet is off",
            },
        ],
        question: "Two adversaries still win here. Name them, and say what each one gets.",
        answer: "A3 and A4, and they are different kinds of loss. A3 is a key compromise at \
                 some future time T: with no ratchet, one key covers every message the session \
                 ever sent, so a single compromise opens the whole archive rather than one \
                 message. A4 is a quantum adversary who does not need access today at all — \
                 X25519 traffic recorded now falls whenever the discrete log does, which is why \
                 harvest-now-decrypt-later is a deadline and not a threat. Neither shows up in \
                 the verdict, which is the point: the recovery panel says what an attacker gets \
                 today, and these are both statements about later.",
        solution: pre_quantum(no_ratchet(full())),
        needs_backend: Some("x25519"),
    },
    Challenge {
        id: "smallest-pad",
        title: "The smallest two-time pad",
        brief: "Build the smallest configuration in which repeating the nonce lets an \
                adversary recover message 2 from a crib for message 1. Every switch you leave \
                on has to be necessary: if one of them can be switched off without changing \
                the result, the configuration is not the smallest.",
        requirements: &[
            Requirement::Verdict {
                tag: "KeystreamReuse",
                label: "The adversary recovers message 2 from a crib for message 1",
            },
            Requirement::Minimal {
                label: "Every switch left on is load-bearing — turning any one off changes the result",
            },
        ],
        question: "Why does each condition you kept have to be there? Key agreement in \
                   particular: why does switching it off make the result worse rather than \
                   better?",
        answer: "Key agreement has to stay on, and that is the counterintuitive one. Switch it \
                 off and the adversary stops needing the two-time pad at all — they rebuild the \
                 key from a transcript that crossed the wire in the clear and read both \
                 messages directly. That is a bigger break and a completely different lesson, so \
                 a configuration that produces it is not a smaller answer to this question but a \
                 wrong one. AEAD has to stay on for the same reason: with nothing encrypted \
                 there is no keystream to reuse. The ratchet has to be off, because a fresh key \
                 per message means the two frames share a nonce and nothing else. And \
                 authentication has to be off — not because it would prevent the attack, but \
                 because it does nothing against it, and a switch that changes no result is \
                 exactly what \"smallest\" excludes.",
        solution: Setup {
            layers: Layers {
                key_agreement: true,
                aead: true,
                transport: false,
                authenticate: false,
                ratchet: false,
                nonce_reuse: true,
            },
            adversary_knows_transport: false,
            kem: None,
        },
        needs_backend: None,
    },
];

/// Score a configuration against a challenge, condition by condition.
///
/// Returns one flag per requirement, in order, so the page can show a checklist
/// rather than a pass/fail. Someone three conditions into a four-condition goal
/// needs to know which one is missing.
pub fn evaluate(
    ch: &Challenge,
    kem: &dyn crate::kem::Kem,
    setup: Setup,
    suite: crate::aead::Suite,
    m1: &[u8],
    m2: &[u8],
) -> crate::error::Result<Vec<bool>> {
    let run = |s: Setup| -> crate::error::Result<crate::session::Exchange> {
        crate::session::exchange(kem, s.layers, suite, s.adversary_knows_transport, m1, m2)
    };
    let ex = run(setup)?;
    let verdict = ex.recovery.tag();
    // The KEM *in force*, not the one selected: with key agreement off the
    // harness substitutes a static backend, and crediting the reader with a
    // post-quantum property the channel does not have would make the checklist
    // lie in the reader's favour.
    let kem_is_pq = ex.sender.hs.kem_is_pq;
    let adversaries = crate::threat::assess(setup.layers, kem_is_pq);

    let mut out = Vec::with_capacity(ch.requirements.len());
    for req in ch.requirements {
        out.push(match req {
            Requirement::Adversary { id, status, .. } => adversaries
                .iter()
                .any(|a| a.id == *id && a.status.as_str() == *status),
            Requirement::PostQuantum { yes, .. } => kem_is_pq == *yes,
            Requirement::Switch { id, on, .. } => switch_of(&setup, id) == Some(*on),
            Requirement::Verdict { tag, .. } => verdict == *tag,
            Requirement::Minimal { .. } => {
                let mut minimal = true;
                for id in SWITCHES {
                    // The injected fault is the premise of the task, not a layer
                    // whose necessity is in question.
                    if id == "nonceReuse" || switch_of(&setup, id) != Some(true) {
                        continue;
                    }
                    let mut without = setup;
                    set_switch(&mut without, id, false);
                    if run(without)?.recovery.tag() == verdict {
                        minimal = false;
                        break;
                    }
                }
                minimal
            }
        });
    }
    Ok(out)
}

fn switch_of(s: &Setup, id: &str) -> Option<bool> {
    Some(match id {
        "keyAgreement" => s.layers.key_agreement,
        "aead" => s.layers.aead,
        "transport" => s.layers.transport,
        "authenticate" => s.layers.authenticate,
        "ratchet" => s.layers.ratchet,
        "nonceReuse" => s.layers.nonce_reuse,
        "adversaryKnowsTransport" => s.adversary_knows_transport,
        _ => return None,
    })
}

fn set_switch(s: &mut Setup, id: &str, on: bool) {
    match id {
        "keyAgreement" => s.layers.key_agreement = on,
        "aead" => s.layers.aead = on,
        "transport" => s.layers.transport = on,
        "authenticate" => s.layers.authenticate = on,
        "ratchet" => s.layers.ratchet = on,
        "nonceReuse" => s.layers.nonce_reuse = on,
        "adversaryKnowsTransport" => s.adversary_knows_transport = on,
        _ => {}
    }
}
