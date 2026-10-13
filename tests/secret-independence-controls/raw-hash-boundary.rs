use libcrux_secrets::U8;

fn main() {
    let input = [U8(0x42); 32];
    let mut digest = [0u8; 32];
    libcrux_sha3::portable::sha256(&mut digest, &input);
}
