mod external {
    extern "C" {
        pub fn write_state (key: *const u8, key_len: u32, value: *const u8, value_len: u32);
        pub fn read_state (key: *const u8, key_len: u32) -> i32;
        pub fn from_memory(result: *const u8, result_len: i32);
    }
}

#[no_mangle]
pub fn write(key: &str, value: &[u8]) {
    unsafe { external::write_state(key.as_ptr(), key.len() as u32, value.as_ptr(), value.len() as u32) }
}

#[no_mangle]
pub fn read(key: &str) -> Vec<u8> {
    let mut val_len = 0;
    unsafe {
        val_len = external::read_state(key.as_ptr(), key.len() as u32);
    }
    let mut value_holder: Vec<u8> = Vec::with_capacity(val_len as usize);
    unsafe {
        external::from_memory(value_holder.as_ptr(), val_len);
    }
    value_holder

}
