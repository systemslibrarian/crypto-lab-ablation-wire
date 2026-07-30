//! # codetalker-core
//!
//! The 1942 Navajo code-talker stack was three layers: a homophonic
//! substitution, a pre-shared codebook, and a rare unwritten language. This
//! crate rebuilds that stack on modern primitives and makes each layer
//! independently switchable, so a reader can discover for themselves which one
//! was actually load-bearing.
//!
//! The historical answer is the pre-shared codebook. Joe Kieyoomia was a fluent
//! Navajo speaker in Japanese custody and could not read the traffic, because
//! the layer everyone romanticises — the language — was the weakest of the
//! three.
//!
//! ## Layer map
//!
//! | 1942 | here |
//! |---|---|
//! | codebook | [`kem`] + [`kdf`] + [`handshake`] |
//! | homophonic substitution | [`aead`] |
//! | rare language | [`transport`] |
//! | *(absent in 1942)* | [`identity`] — peer authentication |
//! | *(absent in 1942)* | [`ratchet`] — forward secrecy |
//!
//! ## Honest limitations
//!
//! - [`transport`] is deliberately trivial. See its module docs.
//! - Constant-time behaviour is not guaranteed under `wasm32`. The browser JIT
//!   makes no such promise regardless of what this source says.

// The crate contained no `unsafe` before this line existed, which is a different
// claim from being unable to contain any. `forbid` makes the compiler the thing
// enforcing it rather than a reader's grep; a crate handling key material should
// not be able to acquire a raw pointer by accident in review.
#![forbid(unsafe_code)]
// The layer-map table above is built out of intra-doc links. A link that stops
// resolving still renders -- as plain text, silently -- so the table would go on
// looking right while no longer pointing anywhere. Denied rather than warned
// because there is no version of a broken link that is acceptable.
//
// `missing_docs` was tried here and removed. It flagged 71 items, nearly all of
// them enum variants and small accessors whose names already say what they are;
// satisfying it would have meant 71 restatements, and filler docs in a crate
// meant to be read are worse than none.
#![deny(rustdoc::broken_intra_doc_links)]

pub mod aead;
pub mod error;
pub mod explain;
pub mod handshake;
pub mod identity;
pub mod kdf;
pub mod kem;
pub mod lab;
pub mod ratchet;
pub mod session;
pub mod threat;
pub mod transcript;
pub mod transport;

pub use error::{Error, Result};
pub use session::{adversary, establish, exchange, Channel, Exchange, Frame, Layers, Recovery};
