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

pub mod aead;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod kdf;
pub mod kem;
pub mod ratchet;
pub mod session;
pub mod transcript;
pub mod transport;

pub use error::{Error, Result};
pub use session::{adversary, establish, Channel, Frame, Layers, Recovery};
