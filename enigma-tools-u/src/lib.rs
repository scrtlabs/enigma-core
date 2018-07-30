#![crate_type = "lib"]

#[macro_use]
extern crate failure;
extern crate reqwest;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate rlp;
extern crate libc;
extern crate tiny_keccak;
extern crate base64;
extern crate openssl;
extern crate rustc_hex as hex;
// webv3 utils
extern crate web3;
// SGX Libraries
extern crate sgx_types;
extern crate sgx_urts;

pub mod attestation_service;
pub mod common_u;
pub mod web3_utils;
pub mod esgx;

use sgx_types::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
