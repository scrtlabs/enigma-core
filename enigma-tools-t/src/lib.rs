#![no_std]
#![crate_type = "lib"]
#![warn(unused_extern_crates)]

extern crate enigma_types;
extern crate enigma_crypto;
extern crate enigma_tools_m;

#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate failure;
extern crate json_patch;
extern crate parity_wasm;
extern crate pwasm_utils;
extern crate sgx_tse;
extern crate sgx_tseal;
extern crate sgx_types;

extern crate bigint;
extern crate hexutil;
extern crate rlp;
extern crate wasmi;
extern crate rustc_hex;

#[macro_use]
pub mod macros;

pub mod build_arguments_g;
pub mod common;
pub mod quote_t;
pub mod document_storage_t; //TODO: Copy of storage_t with more generic naming convention
pub mod storage_t;
pub mod esgx;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
