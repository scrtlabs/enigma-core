#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![deny(unused_extern_crates, missing_docs)]
//! # Enigma Tools Mutual
//! This library provides tools for both untrusted and trusted sides of the SGX. <br>
//! It should supersede both `enigma-tools-t` and `enigma-tools-u`. <br?
//! it abstracts std as `localstd` to and a lot of other library are abstracted via cfg conditions. <br>
//! This crate is Rust 2018 Edition,
//! meaning there's no `extern crate` and `use` statements need to start with `crate`/`self`/`super`.

mod common;
pub mod keeper_types;
pub mod primitives;
pub use crate::common::errors::ToolsError;
pub use crate::common::utils;

#[cfg(feature = "std")]
use {ethabi_std as ethabi, ethereum_types_std as ethereum_types, rmp_serde_std as rmp_serde, serde_json_std as serde_json,
     serde_std as serde, std as localstd};

#[cfg(feature = "sgx")]
use {ethabi_sgx as ethabi, ethereum_types_sgx as ethereum_types, rmp_serde_sgx as rmp_serde, serde_json_sgx as serde_json,
     serde_sgx as serde, sgx_tstd as localstd};
