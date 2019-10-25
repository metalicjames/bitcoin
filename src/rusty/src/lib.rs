use rand::{thread_rng, Rng};

#[no_mangle]
pub extern "C" fn get_secure_random_u64() -> u64 {
    thread_rng().gen::<u64>()
}
