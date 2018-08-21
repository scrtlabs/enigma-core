#![no_std]

#[cfg(not(test))]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate serde_json;

pub mod tests {
    pub fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
