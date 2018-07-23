#![crate_type = "lib"]

#[macro_use]
extern crate failure;
extern crate reqwest;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate rlp;
// webv3 utils 
extern crate web3;
extern crate libc;
extern crate rustc_hex;
extern crate tiny_keccak;
// enigma contract 
extern crate sgx_types;
// esgx 
extern crate sgx_urts;
extern crate base64;

pub mod attestation_service;
pub mod common_u;
pub mod web3_utils;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
