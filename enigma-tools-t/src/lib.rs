#![no_std]
#![crate_type = "lib"]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate failure;
extern crate rmp_serde as rmps;
extern crate json_patch;
extern crate sgx_types;
extern crate sgx_trts;
extern crate sgx_tse;
extern crate sgx_tseal;

extern crate ring;
extern crate tiny_keccak;
extern crate secp256k1;
extern crate wasmi;

pub mod cryptography_t;
pub mod common;
pub mod quote_t;
pub mod storage_t;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
