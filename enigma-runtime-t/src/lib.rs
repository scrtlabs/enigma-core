#![no_std]

#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate serde_json;
extern crate serde;
extern crate rmp_serde as rmps;
extern crate enigma_tools_t;

pub mod state;

pub mod tests {
    pub fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
