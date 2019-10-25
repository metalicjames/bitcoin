extern crate getrandom;

#[no_mangle]
pub extern "C" fn get_secure_random_uint32() -> u32 {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).unwrap();

    ((buf[0] as u32) << 24) |
    ((buf[1] as u32) << 16) |
    ((buf[2] as u32) << 8) |
    buf[3] as u32
}
