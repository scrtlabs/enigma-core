#![no_std]

#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_types;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate rmp_serde as rmps;
extern crate enigma_tools_t;
extern crate json_patch;

pub mod state;
pub mod ocalls_t;

pub mod tests {
    pub fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
