//! Secret-classified portable SHA-3 and SHAKE operations.
//!
//! Loop bounds and array indices depend only on public lengths. Message bytes,
//! Keccak lanes, and digest bytes remain classified throughout the sponge.

use libcrux_secrets::{CastOps, U64, U8};

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const ROTATION: [[u32; 5]; 5] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

#[inline(always)]
fn permutation(state: &mut [U64; 25]) {
    for &round_constant in &ROUND_CONSTANTS {
        let mut columns = [U64(0); 5];
        for x in 0..5 {
            columns[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        let mut theta = [U64(0); 5];
        for x in 0..5 {
            theta[x] = columns[(x + 4) % 5] ^ columns[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= theta[x];
            }
        }

        let old = *state;
        for y in 0..5 {
            for x in 0..5 {
                let destination_x = y;
                let destination_y = (2 * x + 3 * y) % 5;
                state[destination_x + 5 * destination_y] = old[x + 5 * y].rotate_left(ROTATION[y][x]);
            }
        }

        let old = *state;
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] = old[x + 5 * y] ^ ((!old[(x + 1) % 5 + 5 * y]) & old[(x + 2) % 5 + 5 * y]);
            }
        }

        state[0] ^= U64(round_constant);
    }
}

#[inline(always)]
fn absorb_block<const RATE: usize>(state: &mut [U64; 25], input: &[U8], start: usize) {
    for lane in 0..RATE / 8 {
        let mut word = U64(0);
        for byte in 0..8 {
            word |= input[start + lane * 8 + byte].as_u64() << (8 * byte);
        }
        state[lane] ^= word;
    }
    permutation(state);
}

#[inline(always)]
fn absorb_last<const RATE: usize, const DELIMITER: u8>(state: &mut [U64; 25], input: &[U8], start: usize) {
    let remaining = input.len() - start;
    let mut block = [U8(0); RATE];
    block[..remaining].copy_from_slice(&input[start..]);
    block[remaining] = U8(DELIMITER);
    block[RATE - 1] |= U8(0x80);
    absorb_block::<RATE>(state, &block, 0);
}

#[inline(always)]
fn squeeze_block<const RATE: usize>(state: &[U64; 25], output: &mut [U8]) {
    for (position, byte) in output.iter_mut().enumerate() {
        debug_assert!(position < RATE);
        let lane = position / 8;
        let shift = 8 * (position % 8);
        *byte = (state[lane] >> shift).as_u8();
    }
}

#[inline]
fn keccak<const RATE: usize, const DELIMITER: u8>(input: &[U8], output: &mut [U8]) {
    let mut state = [U64(0); 25];
    let full_blocks = input.len() / RATE;
    for block in 0..full_blocks {
        absorb_block::<RATE>(&mut state, input, block * RATE);
    }
    absorb_last::<RATE, DELIMITER>(&mut state, input, full_blocks * RATE);

    let mut written = 0;
    while written < output.len() {
        let take = core::cmp::min(RATE, output.len() - written);
        squeeze_block::<RATE>(&state, &mut output[written..written + take]);
        written += take;
        if written < output.len() {
            permutation(&mut state);
        }
    }
}

/// SHA3-256 over secret-classified bytes.
#[inline(always)]
pub fn sha256(output: &mut [U8; 32], input: &[U8]) {
    keccak::<136, 0x06>(input, output);
}

/// SHA3-512 over secret-classified bytes.
#[inline(always)]
pub fn sha512(output: &mut [U8; 64], input: &[U8]) {
    keccak::<72, 0x06>(input, output);
}

/// SHAKE128 over secret-classified bytes.
#[inline(always)]
pub fn shake128(output: &mut [U8], input: &[U8]) {
    keccak::<168, 0x1f>(input, output);
}

/// SHAKE256 over secret-classified bytes.
#[inline(always)]
pub fn shake256(output: &mut [U8], input: &[U8]) {
    keccak::<136, 0x1f>(input, output);
}
