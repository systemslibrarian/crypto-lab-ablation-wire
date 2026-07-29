//! Key encapsulation, behind one trait.
//!
//! Every third-party KEM binding lives in this module and nowhere else. If an
//! upstream API changes, exactly one file needs editing.
//!
//! The trait is a genuine KEM interface — separate keygen, encapsulate and
//! decapsulate — rather than a single `agree()` that quietly plays both roles.
//! That distinction matters: a function generating both keypairs locally is a
//! simulation of a handshake, not a handshake.

use crate::error::{Error, Result};
use zeroize::Zeroize;

macro_rules! bytes_newtype {
    ($name:ident) => {
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(pub Vec<u8>);
        impl $name {
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}({} bytes)", stringify!($name), self.0.len())
            }
        }
    };
}

bytes_newtype!(PublicKey);
bytes_newtype!(Ciphertext);

/// Secret key material. Zeroized on drop, never printed.
pub struct SecretKey(pub(crate) Vec<u8>);
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretKey(redacted)")
    }
}

/// Shared secret. Zeroized on drop, never printed.
#[derive(Clone)]
pub struct SharedSecret(pub(crate) Vec<u8>);
impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SharedSecret(redacted)")
    }
}

/// A key encapsulation mechanism.
///
/// The session layer never learns whether this is classical, post-quantum or
/// hybrid — which is the whole reason the X-Wing swap is a one-line change.
pub trait Kem {
    fn name(&self) -> &'static str;
    fn is_pq(&self) -> bool;

    fn keygen(&self) -> Result<(SecretKey, PublicKey)>;
    fn encapsulate(&self, pk: &PublicKey) -> Result<(SharedSecret, Ciphertext)>;
    fn decapsulate(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret>;
}

/// DHKEM over X25519, as used by HPKE (RFC 9180 §4.1).
///
/// Encapsulation generates an ephemeral keypair, performs the Diffie-Hellman
/// against the recipient's public key, and ships the ephemeral public key as
/// the ciphertext. Not post-quantum; present as the pre-PQ baseline.
#[cfg(feature = "classical")]
pub struct X25519Kem;

#[cfg(feature = "classical")]
impl Kem for X25519Kem {
    fn name(&self) -> &'static str {
        "DHKEM(X25519)"
    }
    fn is_pq(&self) -> bool {
        false
    }

    fn keygen(&self) -> Result<(SecretKey, PublicKey)> {
        use x25519_dalek::{PublicKey as XPk, StaticSecret};
        let sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let pk = XPk::from(&sk);
        Ok((
            SecretKey(sk.to_bytes().to_vec()),
            PublicKey(pk.as_bytes().to_vec()),
        ))
    }

    fn encapsulate(&self, pk: &PublicKey) -> Result<(SharedSecret, Ciphertext)> {
        use x25519_dalek::{EphemeralSecret, PublicKey as XPk};
        let peer: [u8; 32] =
            pk.0.as_slice()
                .try_into()
                .map_err(|_| Error::Kem("bad public key length"))?;
        let eph = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let eph_pk = XPk::from(&eph);
        let ss = eph.diffie_hellman(&XPk::from(peer));
        if !ss.was_contributory() {
            return Err(Error::Kem("non-contributory shared secret (low-order point)"));
        }
        Ok((
            SharedSecret(ss.as_bytes().to_vec()),
            Ciphertext(eph_pk.as_bytes().to_vec()),
        ))
    }

    fn decapsulate(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret> {
        use x25519_dalek::{PublicKey as XPk, StaticSecret};
        let skb: [u8; 32] =
            sk.0.as_slice()
                .try_into()
                .map_err(|_| Error::Kem("bad secret key length"))?;
        let ctb: [u8; 32] =
            ct.0.as_slice()
                .try_into()
                .map_err(|_| Error::Kem("bad ciphertext length"))?;
        let ss = StaticSecret::from(skb).diffie_hellman(&XPk::from(ctb));
        if !ss.was_contributory() {
            return Err(Error::Kem("non-contributory shared secret (low-order point)"));
        }
        Ok(SharedSecret(ss.as_bytes().to_vec()))
    }
}

/// Bridge between the two `rand_core` generations in this dependency tree.
///
/// `libcrux-kem` takes its randomness through `rand_core` 0.10's `CryptoRng`;
/// every other module here is on 0.6. Depending on both `rand_core` 0.10 *and*
/// `rand 0.10`'s `SysRng` would put a second entropy backend in the tree — and
/// on `wasm32-unknown-unknown` that backend needs a build-time cfg the browser
/// demo has no way to set. Forwarding to the `OsRng` already in use keeps one
/// source of randomness for the whole crate.
///
/// This adds no logic of its own: every method delegates straight to `OsRng`.
#[cfg(feature = "pq")]
mod libcrux_rng {
    use rand_core::RngCore as _;

    pub struct OsRng;

    impl rand_core_010::TryRng for OsRng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
            Ok(rand_core::OsRng.next_u32())
        }
        fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
            Ok(rand_core::OsRng.next_u64())
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
            rand_core::OsRng.fill_bytes(dst);
            Ok(())
        }
    }

    // OsRng is a CSPRNG on both sides of the bridge; the marker carries over.
    impl rand_core_010::TryCryptoRng for OsRng {}
}

/// Hybrid X25519 + ML-KEM-768, per the X-Wing draft.
/// Secure if *either* component holds. That is the entire point.
#[cfg(feature = "pq")]
pub struct XWingKem;

#[cfg(feature = "pq")]
impl Kem for XWingKem {
    fn name(&self) -> &'static str {
        "X-Wing (X25519 + ML-KEM-768)"
    }
    fn is_pq(&self) -> bool {
        true
    }

    fn keygen(&self) -> Result<(SecretKey, PublicKey)> {
        let (sk, pk) = libcrux_kem::key_gen(libcrux_kem::Algorithm::XWingKemDraft06, &mut libcrux_rng::OsRng)
            .map_err(|_| Error::Kem("keygen"))?;
        Ok((SecretKey(sk.encode()), PublicKey(pk.encode())))
    }

    fn encapsulate(&self, pk: &PublicKey) -> Result<(SharedSecret, Ciphertext)> {
        let pk = libcrux_kem::PublicKey::decode(libcrux_kem::Algorithm::XWingKemDraft06, &pk.0)
            .map_err(|_| Error::Kem("decode public key"))?;
        let (ss, ct) = pk
            .encapsulate(&mut libcrux_rng::OsRng)
            .map_err(|_| Error::Kem("encapsulate"))?;
        Ok((SharedSecret(ss.encode()), Ciphertext(ct.encode())))
    }

    fn decapsulate(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret> {
        let sk = libcrux_kem::PrivateKey::decode(libcrux_kem::Algorithm::XWingKemDraft06, &sk.0)
            .map_err(|_| Error::Kem("decode secret key"))?;
        let ct = libcrux_kem::Ct::decode(libcrux_kem::Algorithm::XWingKemDraft06, &ct.0)
            .map_err(|_| Error::Kem("decode ciphertext"))?;
        let ss = ct.decapsulate(&sk).map_err(|_| Error::Kem("decapsulate"))?;
        Ok(SharedSecret(ss.encode()))
    }
}

/// Raw ML-KEM-768 decapsulation, for the FIPS 203 known-answer tests.
///
/// X-Wing is X25519 combined with ML-KEM-768, so this exercises the
/// post-quantum half of the hybrid directly against the ACVP vectors. It is not
/// part of the [`Kem`] surface and the session layer never calls it — but the
/// binding belongs in this module like every other, and a KAT that cannot reach
/// the implementation is a KAT that proves nothing.
#[cfg(feature = "pq")]
pub fn mlkem768_decapsulate(dk: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let sk = libcrux_kem::PrivateKey::decode(libcrux_kem::Algorithm::MlKem768, dk)
        .map_err(|_| Error::Kem("decode ml-kem-768 decapsulation key"))?;
    let ct = libcrux_kem::Ct::decode(libcrux_kem::Algorithm::MlKem768, ct)
        .map_err(|_| Error::Kem("decode ml-kem-768 ciphertext"))?;
    Ok(ct
        .decapsulate(&sk)
        .map_err(|_| Error::Kem("ml-kem-768 decapsulate"))?
        .encode())
}

/// The captured-codebook case: a fixed keypair with a fixed shared secret.
/// Models "no key agreement at all" so the ablation harness has something to
/// compare against. Deliberately, obviously insecure.
pub struct StaticKem;

impl Kem for StaticKem {
    fn name(&self) -> &'static str {
        "static (captured codebook)"
    }
    fn is_pq(&self) -> bool {
        false
    }
    fn keygen(&self) -> Result<(SecretKey, PublicKey)> {
        Ok((SecretKey(vec![0x11; 32]), PublicKey(vec![0x22; 32])))
    }
    fn encapsulate(&self, _pk: &PublicKey) -> Result<(SharedSecret, Ciphertext)> {
        Ok((SharedSecret(vec![0x2a; 32]), Ciphertext(vec![0x33; 32])))
    }
    fn decapsulate(&self, _sk: &SecretKey, _ct: &Ciphertext) -> Result<SharedSecret> {
        Ok(SharedSecret(vec![0x2a; 32]))
    }
}

pub fn backend(name: &str) -> Result<Box<dyn Kem>> {
    match name {
        "static" => Ok(Box::new(StaticKem)),
        #[cfg(feature = "classical")]
        "x25519" => Ok(Box::new(X25519Kem)),
        #[cfg(feature = "pq")]
        "xwing" => Ok(Box::new(XWingKem)),
        #[cfg(not(feature = "classical"))]
        "x25519" => Err(Error::BackendUnavailable("x25519 (feature `classical`)")),
        #[cfg(not(feature = "pq"))]
        "xwing" => Err(Error::BackendUnavailable("xwing (feature `pq`)")),
        _ => Err(Error::Kem("unknown backend")),
    }
}
