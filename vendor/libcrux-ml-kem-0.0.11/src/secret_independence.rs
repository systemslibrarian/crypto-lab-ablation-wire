//! Secret-classified ML-KEM path for the low-level `arrayref::Kem` contract.
//!
//! The released high-level API stores randomness, private keys, and shared
//! secrets in raw byte arrays. This module keeps those values as
//! `libcrux_secrets::U8` through hashing, sampling, polynomial serialization,
//! Fujisaki-Okamoto re-encryption, and constant-time selection. Only ML-KEM's
//! specified public outputs (encapsulation keys and ciphertexts), plus the
//! public-key subsection embedded in a decapsulation key, are declassified.

use core::array::from_fn;

use libcrux_secrets::{CastOps, Declassify, Select, I16, U32, U8};

use crate::{
    constants::{BYTES_PER_RING_ELEMENT, H_DIGEST_SIZE, SHARED_SECRET_SIZE},
    hash_functions::portable::PortableHash,
    ind_cpa::{self, unpacked::IndCpaPublicKeyUnpacked},
    matrix::{compute_As_plus_e, compute_message, compute_ring_element_v, compute_vector_u},
    ntt::ntt_binomially_sampled_ring_element,
    polynomial::{PolynomialRingElement, VECTORS_IN_RING_ELEMENT},
    serialize::deserialize_then_decompress_ring_element_v,
    vector::{portable, Operations},
};

type Vector = portable::PortableVector;

#[inline(always)]
fn hash_g(input: &[U8]) -> [U8; 64] {
    let mut output = [U8(0); 64];
    libcrux_sha3::secret::sha512(&mut output, input);
    output
}

#[inline(always)]
fn hash_h(input: &[U8]) -> [U8; 32] {
    let mut output = [U8(0); 32];
    libcrux_sha3::secret::sha256(&mut output, input);
    output
}

#[inline(always)]
fn prf<const LEN: usize>(input: &[U8]) -> [U8; LEN] {
    let mut output = [U8(0); LEN];
    libcrux_sha3::secret::shake256(&mut output, input);
    output
}

#[inline(always)]
fn classify_public<const LEN: usize>(input: &[u8]) -> [U8; LEN] {
    debug_assert_eq!(input.len(), LEN);
    let mut output = [U8(0); LEN];
    for i in 0..LEN {
        output[i] = U8(input[i]);
    }
    output
}

#[inline(always)]
fn declassify_public<const LEN: usize>(input: &[U8]) -> [u8; LEN] {
    debug_assert_eq!(input.len(), LEN);
    let mut output = [0u8; LEN];
    for i in 0..LEN {
        output[i] = input[i].declassify();
    }
    output
}

#[inline(always)]
fn polynomial_from_secret_i16(input: &[I16; 256]) -> PolynomialRingElement<Vector> {
    let mut output = PolynomialRingElement::<Vector>::ZERO();
    for i in 0..VECTORS_IN_RING_ELEMENT {
        output.coefficients[i] = portable::secret_from_i16_array(&input[i * 16..(i + 1) * 16]);
    }
    output
}

#[inline(always)]
fn sample_cbd_2(randomness: &[U8]) -> PolynomialRingElement<Vector> {
    debug_assert_eq!(randomness.len(), 128);
    let mut sampled = [I16(0); 256];
    for (chunk_number, bytes) in randomness.chunks_exact(4).enumerate() {
        let bits = U32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let tosses = (bits & 0x5555_5555) + ((bits >> 1) & 0x5555_5555);
        for outcome_set in (0..32u32).step_by(4) {
            let first = ((tosses >> outcome_set) & 0x3).as_i16();
            let second = ((tosses >> (outcome_set + 2)) & 0x3).as_i16();
            sampled[8 * chunk_number + (outcome_set >> 2) as usize] = first - second;
        }
    }
    polynomial_from_secret_i16(&sampled)
}

#[inline(always)]
fn sample_cbd_3(randomness: &[U8]) -> PolynomialRingElement<Vector> {
    debug_assert_eq!(randomness.len(), 192);
    let mut sampled = [I16(0); 256];
    for (chunk_number, bytes) in randomness.chunks_exact(3).enumerate() {
        let bits = bytes[0].as_u32() | (bytes[1].as_u32() << 8) | (bytes[2].as_u32() << 16);
        let tosses = (bits & 0x0024_9249) + ((bits >> 1) & 0x0024_9249) + ((bits >> 2) & 0x0024_9249);
        for outcome_set in (0..24u32).step_by(6) {
            let first = ((tosses >> outcome_set) & 0x7).as_i16();
            let second = ((tosses >> (outcome_set + 3)) & 0x7).as_i16();
            sampled[4 * chunk_number + (outcome_set / 6) as usize] = first - second;
        }
    }
    polynomial_from_secret_i16(&sampled)
}

#[inline(always)]
fn sample_cbd<const ETA: usize>(randomness: &[U8]) -> PolynomialRingElement<Vector> {
    match ETA {
        2 => sample_cbd_2(randomness),
        3 => sample_cbd_3(randomness),
        _ => unreachable!("ML-KEM eta must be 2 or 3"),
    }
}

#[inline(always)]
fn sample_vector_then_ntt<const K: usize, const ETA: usize, const RANDOMNESS_SIZE: usize>(
    seed: &[U8; 32],
    domain_start: u8,
) -> ([PolynomialRingElement<Vector>; K], u8) {
    let mut output = from_fn(|_| PolynomialRingElement::<Vector>::ZERO());
    for i in 0..K {
        let mut input = [U8(0); 33];
        input[..32].copy_from_slice(seed);
        input[32] = U8(domain_start.wrapping_add(i as u8));
        let randomness: [U8; RANDOMNESS_SIZE] = prf(&input);
        output[i] = sample_cbd::<ETA>(&randomness);
        ntt_binomially_sampled_ring_element(&mut output[i]);
    }
    (output, domain_start.wrapping_add(K as u8))
}

#[inline(always)]
fn sample_vector<const K: usize, const ETA: usize, const RANDOMNESS_SIZE: usize>(
    seed: &[U8; 32],
    domain_start: u8,
) -> ([PolynomialRingElement<Vector>; K], u8) {
    let mut output = from_fn(|_| PolynomialRingElement::<Vector>::ZERO());
    for i in 0..K {
        let mut input = [U8(0); 33];
        input[..32].copy_from_slice(seed);
        input[32] = U8(domain_start.wrapping_add(i as u8));
        let randomness: [U8; RANDOMNESS_SIZE] = prf(&input);
        output[i] = sample_cbd::<ETA>(&randomness);
    }
    (output, domain_start.wrapping_add(K as u8))
}

#[inline(always)]
fn serialize_polynomial_12(polynomial: &PolynomialRingElement<Vector>) -> [U8; BYTES_PER_RING_ELEMENT] {
    let mut output = [U8(0); BYTES_PER_RING_ELEMENT];
    for i in 0..VECTORS_IN_RING_ELEMENT {
        let coefficients = Vector::to_unsigned_representative(polynomial.coefficients[i]);
        let bytes = portable::secret_serialize_12(coefficients);
        output[i * 24..(i + 1) * 24].copy_from_slice(&bytes);
    }
    output
}

#[inline(always)]
fn deserialize_polynomial_12(input: &[U8]) -> PolynomialRingElement<Vector> {
    debug_assert_eq!(input.len(), BYTES_PER_RING_ELEMENT);
    let mut output = PolynomialRingElement::<Vector>::ZERO();
    for (i, bytes) in input.chunks_exact(24).enumerate() {
        output.coefficients[i] = portable::secret_deserialize_12(bytes);
    }
    output
}

#[inline(always)]
fn serialize_private_vector<const K: usize, const LEN: usize>(
    vector: &[PolynomialRingElement<Vector>; K],
) -> [U8; LEN] {
    debug_assert_eq!(LEN, K * BYTES_PER_RING_ELEMENT);
    let mut output = [U8(0); LEN];
    for i in 0..K {
        output[i * BYTES_PER_RING_ELEMENT..(i + 1) * BYTES_PER_RING_ELEMENT]
            .copy_from_slice(&serialize_polynomial_12(&vector[i]));
    }
    output
}

#[inline(always)]
fn deserialize_private_vector<const K: usize>(input: &[U8]) -> [PolynomialRingElement<Vector>; K] {
    debug_assert_eq!(input.len(), K * BYTES_PER_RING_ELEMENT);
    from_fn(|i| {
        deserialize_polynomial_12(&input[i * BYTES_PER_RING_ELEMENT..(i + 1) * BYTES_PER_RING_ELEMENT])
    })
}

#[inline(always)]
fn serialize_public_key<const K: usize, const LEN: usize>(
    public_key: &IndCpaPublicKeyUnpacked<K, Vector>,
    rho: &[U8; 32],
) -> [U8; LEN] {
    let mut output = [U8(0); LEN];
    let ranked = K * BYTES_PER_RING_ELEMENT;
    for i in 0..K {
        output[i * BYTES_PER_RING_ELEMENT..(i + 1) * BYTES_PER_RING_ELEMENT]
            .copy_from_slice(&serialize_polynomial_12(&public_key.t_as_ntt[i]));
    }
    output[ranked..].copy_from_slice(rho);
    output
}

#[inline(always)]
fn deserialize_message(input: &[U8; SHARED_SECRET_SIZE]) -> PolynomialRingElement<Vector> {
    let mut output = PolynomialRingElement::<Vector>::ZERO();
    for i in 0..VECTORS_IN_RING_ELEMENT {
        let compressed = portable::secret_deserialize_1(&input[2 * i..2 * i + 2]);
        output.coefficients[i] = Vector::decompress_1(compressed);
    }
    output
}

#[inline(always)]
fn serialize_message(message: PolynomialRingElement<Vector>) -> [U8; SHARED_SECRET_SIZE] {
    let mut output = [U8(0); SHARED_SECRET_SIZE];
    for i in 0..VECTORS_IN_RING_ELEMENT {
        let coefficient = Vector::to_unsigned_representative(message.coefficients[i]);
        let compressed = Vector::compress_1(coefficient);
        output[2 * i..2 * i + 2].copy_from_slice(&portable::secret_serialize_1(compressed));
    }
    output
}

#[inline(always)]
fn serialize_ciphertext_u<const K: usize, const OUT_LEN: usize, const COMPRESSION_FACTOR: usize>(
    input: [PolynomialRingElement<Vector>; K],
    output: &mut [U8],
) {
    debug_assert_eq!(output.len(), OUT_LEN);
    for (polynomial_index, polynomial) in input.into_iter().enumerate() {
        for i in 0..VECTORS_IN_RING_ELEMENT {
            let coefficient = Vector::to_unsigned_representative(polynomial.coefficients[i]);
            match COMPRESSION_FACTOR {
                10 => {
                    let bytes = portable::secret_serialize_10(Vector::compress::<10>(coefficient));
                    let start = polynomial_index * (OUT_LEN / K) + i * 20;
                    output[start..start + 20].copy_from_slice(&bytes);
                }
                11 => {
                    let bytes = portable::secret_serialize_11(Vector::compress::<11>(coefficient));
                    let start = polynomial_index * (OUT_LEN / K) + i * 22;
                    output[start..start + 22].copy_from_slice(&bytes);
                }
                _ => unreachable!("ML-KEM u compression must be 10 or 11"),
            }
        }
    }
}

#[inline(always)]
fn serialize_ciphertext_v<const COMPRESSION_FACTOR: usize>(
    polynomial: PolynomialRingElement<Vector>,
    output: &mut [U8],
) {
    for i in 0..VECTORS_IN_RING_ELEMENT {
        let coefficient = Vector::to_unsigned_representative(polynomial.coefficients[i]);
        match COMPRESSION_FACTOR {
            4 => {
                let bytes = portable::secret_serialize_4(Vector::compress::<4>(coefficient));
                output[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
            }
            5 => {
                let bytes = portable::secret_serialize_5(Vector::compress::<5>(coefficient));
                output[i * 10..(i + 1) * 10].copy_from_slice(&bytes);
            }
            _ => unreachable!("ML-KEM v compression must be 4 or 5"),
        }
    }
}

#[inline(always)]
fn encrypt<
    const K: usize,
    const CIPHERTEXT_SIZE: usize,
    const T_AS_NTT_ENCODED_SIZE: usize,
    const C1_SIZE: usize,
    const C2_SIZE: usize,
    const U_COMPRESSION_FACTOR: usize,
    const V_COMPRESSION_FACTOR: usize,
    const ETA1: usize,
    const ETA1_RANDOMNESS_SIZE: usize,
    const ETA2: usize,
    const ETA2_RANDOMNESS_SIZE: usize,
>(
    public_key: &[u8],
    message: &[U8; SHARED_SECRET_SIZE],
    randomness: &[U8; SHARED_SECRET_SIZE],
) -> [U8; CIPHERTEXT_SIZE] {
    let mut unpacked_public_key = IndCpaPublicKeyUnpacked::<K, Vector>::default();
    ind_cpa::build_unpacked_public_key_mut::<K, T_AS_NTT_ENCODED_SIZE, Vector, PortableHash<K>>(
        public_key,
        &mut unpacked_public_key,
    );

    let (r_as_ntt, domain) = sample_vector_then_ntt::<K, ETA1, ETA1_RANDOMNESS_SIZE>(randomness, 0);
    let (error_1, domain) = sample_vector::<K, ETA2, ETA2_RANDOMNESS_SIZE>(randomness, domain);
    let mut final_prf_input = [U8(0); 33];
    final_prf_input[..32].copy_from_slice(randomness);
    final_prf_input[32] = U8(domain);
    let error_2_randomness: [U8; ETA2_RANDOMNESS_SIZE] = prf(&final_prf_input);
    let error_2 = sample_cbd::<ETA2>(&error_2_randomness);

    let u = compute_vector_u(&unpacked_public_key.A, &r_as_ntt, &error_1);
    let message = deserialize_message(message);
    let v = compute_ring_element_v(&unpacked_public_key.t_as_ntt, &r_as_ntt, &error_2, &message);

    let mut ciphertext = [U8(0); CIPHERTEXT_SIZE];
    serialize_ciphertext_u::<K, C1_SIZE, U_COMPRESSION_FACTOR>(u, &mut ciphertext[..C1_SIZE]);
    serialize_ciphertext_v::<V_COMPRESSION_FACTOR>(v, &mut ciphertext[C1_SIZE..C1_SIZE + C2_SIZE]);
    ciphertext
}

#[inline(always)]
fn decrypt<
    const K: usize,
    const CIPHERTEXT_SIZE: usize,
    const C1_SIZE: usize,
    const U_COMPRESSION_FACTOR: usize,
    const V_COMPRESSION_FACTOR: usize,
>(
    private_key: &[U8],
    ciphertext: &[u8; CIPHERTEXT_SIZE],
) -> [U8; SHARED_SECRET_SIZE] {
    let secret_as_ntt = deserialize_private_vector::<K>(private_key);
    let u_as_ntt = ind_cpa::deserialize_then_decompress_u::<K, CIPHERTEXT_SIZE, U_COMPRESSION_FACTOR, Vector>(
        ciphertext,
    );
    let v =
        deserialize_then_decompress_ring_element_v::<K, V_COMPRESSION_FACTOR, Vector>(&ciphertext[C1_SIZE..]);
    serialize_message(compute_message(&v, &secret_as_ntt, &u_as_ntt))
}

pub(crate) fn keygen<
    const K: usize,
    const CPA_PRIVATE_KEY_SIZE: usize,
    const PRIVATE_KEY_SIZE: usize,
    const PUBLIC_KEY_SIZE: usize,
    const ETA1: usize,
    const ETA1_RANDOMNESS_SIZE: usize,
>(
    encapsulation_key: &mut [u8; PUBLIC_KEY_SIZE],
    decapsulation_key: &mut [U8; PRIVATE_KEY_SIZE],
    randomness: &[U8; 64],
) {
    let mut seed_input = [U8(0); 33];
    seed_input[..32].copy_from_slice(&randomness[..32]);
    seed_input[32] = U8(K as u8);
    let expanded = hash_g(&seed_input);
    let mut rho_secret = [U8(0); 32];
    rho_secret.copy_from_slice(&expanded[..32]);
    let mut sigma = [U8(0); 32];
    sigma.copy_from_slice(&expanded[32..]);

    // rho is an algorithm-defined public value and is immediately included in ek.
    let rho: [u8; 32] = declassify_public(&rho_secret);
    let mut public_key_unpacked = IndCpaPublicKeyUnpacked::<K, Vector>::default();
    crate::matrix::sample_matrix_A::<K, Vector, PortableHash<K>>(
        &mut public_key_unpacked.A,
        &{
            let mut padded = [0u8; 34];
            padded[..32].copy_from_slice(&rho);
            padded
        },
        true,
    );
    let (secret_as_ntt, domain) = sample_vector_then_ntt::<K, ETA1, ETA1_RANDOMNESS_SIZE>(&sigma, 0);
    let (error_as_ntt, _) = sample_vector_then_ntt::<K, ETA1, ETA1_RANDOMNESS_SIZE>(&sigma, domain);
    compute_As_plus_e(
        &mut public_key_unpacked.t_as_ntt,
        &public_key_unpacked.A,
        &secret_as_ntt,
        &error_as_ntt,
    );

    let public_key_typed = serialize_public_key::<K, PUBLIC_KEY_SIZE>(&public_key_unpacked, &rho_secret);
    encapsulation_key.copy_from_slice(&declassify_public::<PUBLIC_KEY_SIZE>(&public_key_typed));

    let cpa_private_key = serialize_private_vector::<K, CPA_PRIVATE_KEY_SIZE>(&secret_as_ntt);
    let public_key_hash = hash_h(&public_key_typed);
    let mut offset = 0;
    decapsulation_key[offset..offset + CPA_PRIVATE_KEY_SIZE].copy_from_slice(&cpa_private_key);
    offset += CPA_PRIVATE_KEY_SIZE;
    decapsulation_key[offset..offset + PUBLIC_KEY_SIZE].copy_from_slice(&public_key_typed);
    offset += PUBLIC_KEY_SIZE;
    decapsulation_key[offset..offset + H_DIGEST_SIZE].copy_from_slice(&public_key_hash);
    offset += H_DIGEST_SIZE;
    decapsulation_key[offset..offset + SHARED_SECRET_SIZE].copy_from_slice(&randomness[32..]);
    debug_assert_eq!(offset + SHARED_SECRET_SIZE, PRIVATE_KEY_SIZE);
}

pub(crate) fn encaps<
    const K: usize,
    const CIPHERTEXT_SIZE: usize,
    const PUBLIC_KEY_SIZE: usize,
    const T_AS_NTT_ENCODED_SIZE: usize,
    const C1_SIZE: usize,
    const C2_SIZE: usize,
    const U_COMPRESSION_FACTOR: usize,
    const V_COMPRESSION_FACTOR: usize,
    const ETA1: usize,
    const ETA1_RANDOMNESS_SIZE: usize,
    const ETA2: usize,
    const ETA2_RANDOMNESS_SIZE: usize,
>(
    ciphertext: &mut [u8; CIPHERTEXT_SIZE],
    shared_secret: &mut [U8; SHARED_SECRET_SIZE],
    public_key: &[u8; PUBLIC_KEY_SIZE],
    randomness: &[U8; SHARED_SECRET_SIZE],
) {
    let public_key_typed = classify_public::<PUBLIC_KEY_SIZE>(public_key);
    let public_key_hash = hash_h(&public_key_typed);
    let mut hash_input = [U8(0); 64];
    hash_input[..32].copy_from_slice(randomness);
    hash_input[32..].copy_from_slice(&public_key_hash);
    let expanded = hash_g(&hash_input);
    shared_secret.copy_from_slice(&expanded[..32]);
    let mut coins = [U8(0); 32];
    coins.copy_from_slice(&expanded[32..]);
    let ciphertext_typed = encrypt::<
        K,
        CIPHERTEXT_SIZE,
        T_AS_NTT_ENCODED_SIZE,
        C1_SIZE,
        C2_SIZE,
        U_COMPRESSION_FACTOR,
        V_COMPRESSION_FACTOR,
        ETA1,
        ETA1_RANDOMNESS_SIZE,
        ETA2,
        ETA2_RANDOMNESS_SIZE,
    >(public_key, randomness, &coins);
    ciphertext.copy_from_slice(&declassify_public::<CIPHERTEXT_SIZE>(&ciphertext_typed));
}

pub(crate) fn decaps<
    const K: usize,
    const PRIVATE_KEY_SIZE: usize,
    const CPA_PRIVATE_KEY_SIZE: usize,
    const PUBLIC_KEY_SIZE: usize,
    const CIPHERTEXT_SIZE: usize,
    const T_AS_NTT_ENCODED_SIZE: usize,
    const C1_SIZE: usize,
    const C2_SIZE: usize,
    const U_COMPRESSION_FACTOR: usize,
    const V_COMPRESSION_FACTOR: usize,
    const ETA1: usize,
    const ETA1_RANDOMNESS_SIZE: usize,
    const ETA2: usize,
    const ETA2_RANDOMNESS_SIZE: usize,
    const IMPLICIT_REJECTION_INPUT_SIZE: usize,
>(
    shared_secret: &mut [U8; SHARED_SECRET_SIZE],
    ciphertext: &[u8; CIPHERTEXT_SIZE],
    decapsulation_key: &[U8; PRIVATE_KEY_SIZE],
) {
    let public_key_offset = CPA_PRIVATE_KEY_SIZE;
    let public_key_hash_offset = public_key_offset + PUBLIC_KEY_SIZE;
    let rejection_offset = public_key_hash_offset + H_DIGEST_SIZE;

    // The embedded encapsulation key is public by ML-KEM's key format. It was
    // classified only because the arrayref contract classifies the whole dk.
    let public_key: [u8; PUBLIC_KEY_SIZE] =
        declassify_public(&decapsulation_key[public_key_offset..public_key_hash_offset]);
    let message = decrypt::<K, CIPHERTEXT_SIZE, C1_SIZE, U_COMPRESSION_FACTOR, V_COMPRESSION_FACTOR>(
        &decapsulation_key[..CPA_PRIVATE_KEY_SIZE],
        ciphertext,
    );

    let mut hash_input = [U8(0); 64];
    hash_input[..32].copy_from_slice(&message);
    hash_input[32..].copy_from_slice(&decapsulation_key[public_key_hash_offset..rejection_offset]);
    let expanded = hash_g(&hash_input);
    let mut accepted_secret = [U8(0); 32];
    accepted_secret.copy_from_slice(&expanded[..32]);
    let mut coins = [U8(0); 32];
    coins.copy_from_slice(&expanded[32..]);

    let expected_ciphertext = encrypt::<
        K,
        CIPHERTEXT_SIZE,
        T_AS_NTT_ENCODED_SIZE,
        C1_SIZE,
        C2_SIZE,
        U_COMPRESSION_FACTOR,
        V_COMPRESSION_FACTOR,
        ETA1,
        ETA1_RANDOMNESS_SIZE,
        ETA2,
        ETA2_RANDOMNESS_SIZE,
    >(&public_key, &message, &coins);

    let mut rejection_input = [U8(0); IMPLICIT_REJECTION_INPUT_SIZE];
    rejection_input[..SHARED_SECRET_SIZE].copy_from_slice(&decapsulation_key[rejection_offset..]);
    for i in 0..CIPHERTEXT_SIZE {
        rejection_input[SHARED_SECRET_SIZE + i] = U8(ciphertext[i]);
    }
    let rejected_secret: [U8; SHARED_SECRET_SIZE] = prf(&rejection_input);

    let mut mismatch = U8(0);
    for i in 0..CIPHERTEXT_SIZE {
        mismatch |= expected_ciphertext[i] ^ U8(ciphertext[i]);
    }
    accepted_secret
        .as_mut_slice()
        .select(rejected_secret.as_slice(), mismatch);
    shared_secret.copy_from_slice(&accepted_secret);
}
