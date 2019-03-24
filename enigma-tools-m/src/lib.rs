#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![deny(unused_extern_crates)]

mod common;
pub mod keeper_types;
pub mod primitives;

#[cfg(feature = "std")]
use {ethabi_std as ethabi, ethereum_types_std as ethereum_types, rmp_serde_std as rmp_serde, serde_json_std as serde_json,
     serde_std as serde, std as localstd};

#[cfg(feature = "sgx")]
use {ethabi_sgx as ethabi, ethereum_types_sgx as ethereum_types, rmp_serde_sgx as rmp_serde, serde_json_sgx as serde_json,
     serde_sgx as serde, sgx_tstd as localstd};
