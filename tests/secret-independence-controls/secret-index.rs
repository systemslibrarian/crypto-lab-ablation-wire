use libcrux_secrets::U8;

fn main() {
    let secret_index = U8(1);
    let values = [10u8, 20u8];
    core::hint::black_box(values[secret_index]);
}
