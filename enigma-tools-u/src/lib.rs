#![crate_type = "lib"]
#![warn(unused_extern_crates)]

extern crate enigma_crypto;
extern crate enigma_types;
#[macro_use]
extern crate failure;
extern crate reqwest;
extern crate serde_json;
extern crate base64;
extern crate openssl;
extern crate rlp;
extern crate rustc_hex as hex;
#[macro_use]
extern crate serde;
// web3 utils
extern crate web3;
// SGX Libraries
extern crate sgx_types;
extern crate sgx_urts;
#[macro_use]
extern crate log;
extern crate log4rs;

#[macro_use]
extern crate log_derive;
extern crate ethabi;
extern crate ethereum_types;
extern crate tiny_keccak;

extern crate gethostname;

pub mod attestation_service;
pub mod common_u;
pub mod esgx;
pub mod web3_utils;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
