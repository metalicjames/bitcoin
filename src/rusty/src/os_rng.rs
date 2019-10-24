extern crate getrandom;

#[no_mangle]
pub extern "C" fn get_secure_random_uint32() -> u32 {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf)?;

    buf[0] as u32
}
