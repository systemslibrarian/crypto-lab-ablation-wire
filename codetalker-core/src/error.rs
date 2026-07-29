use core::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Kem(&'static str),
    Kdf,
    Auth(&'static str),
    Aead,
    Transport(&'static str),
    /// The requested KEM backend was not compiled in.
    BackendUnavailable(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Kem(m) => write!(f, "kem failure: {m}"),
            Error::Kdf => write!(f, "kdf failure"),
            Error::Auth(m) => write!(f, "authentication failure: {m}"),
            Error::Aead => write!(f, "aead failure (bad tag, bad key, or bad nonce)"),
            Error::Transport(m) => write!(f, "transport failure: {m}"),
            Error::BackendUnavailable(m) => {
                write!(
                    f,
                    "backend not compiled in: {m} (enable the matching cargo feature)"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
