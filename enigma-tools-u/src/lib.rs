#![crate_type = "lib"]

#[macro_use]
extern crate failure;
extern crate reqwest;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate base64;
extern crate libc;
extern crate openssl;
extern crate rlp;
extern crate bigint;
extern crate rustc_hex as hex;
extern crate serde;
extern crate tiny_keccak;
// web3 utils
extern crate ethabi;
extern crate web3;
// SGX Libraries
extern crate sgx_types;
extern crate sgx_urts;
extern crate ethereum_types;

pub mod attestation_service;
pub mod common_u;
pub mod esgx;
pub mod web3_utils;

use sgx_types::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
