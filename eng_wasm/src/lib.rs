mod external {
    extern "C" {
        pub fn moria() -> i32;
    }
}

#[no_mangle]
pub fn external_function() -> i32{
    unsafe { external::moria() }
}
