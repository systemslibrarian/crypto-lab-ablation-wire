use libcrux_secrets::{CastOps, U8, U64};

fn main() {
    let input = [U8(0x42); 32];
    let mut digest = [U8(0); 32];
    libcrux_sha3::secret::sha256(&mut digest, &input);

    let mut accumulator = U64(0);
    for (index, byte) in digest.into_iter().enumerate() {
        accumulator ^= byte.as_u64() << (index % 8);
    }
    core::hint::black_box(accumulator);
}
