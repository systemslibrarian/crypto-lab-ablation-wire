use libcrux_secrets::U8;

fn main() {
    let secret = U8(1);
    if secret == U8(0) {
        core::hint::black_box(secret);
    }
}
