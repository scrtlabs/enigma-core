//! # Mutual Utils.
//! This module contain some handy utils.
//! Right now only a trait that can convert `[u8; 64]` to a 20 bytes Ethereum address
//! or a 20 bytes Ethereum address String in hex representation.

use crate::localstd::string::String;
use enigma_crypto::hash::Keccak256;
use rustc_hex::ToHex;

#[cfg(feature = "sgx")]
use crate::localstd::sync::{SgxMutex as Mutex, SgxMutexGuard as MutexGuard};

#[cfg(feature = "std")]
use crate::localstd::sync::{Mutex, MutexGuard};

/// A trait that is basically a shortcut for `mutex.lock().expect(format!("{} mutex is posion", name))`
/// you instead call `mutex.lock_expect(name)` and it will act the same.
pub trait LockExpectMutex<T> {
    /// See trait documentation. a shortcut for `lock()` and `expect()`
    fn lock_expect(&self, name: &str) -> MutexGuard<T>;
}

impl<T> LockExpectMutex<T> for Mutex<T> {
    fn lock_expect(&self, name: &str) -> MutexGuard<T> { self.lock().unwrap_or_else(|_| panic!("{} mutex is poison", name)) }
}

/// A trait to convert an object into an Ethereum Address
pub trait EthereumAddress<T, P> {
    /// This should convert the object(by hashing and slicing) into a String type 40 characters Ethereum address.
    fn address_string(&self) -> T
    where T: Sized;
    /// This should convert the object(by hashing and slicing) into a 20 byte Ethereum address.
    fn address(&self) -> P
    where P: Sized;
}

impl EthereumAddress<String, [u8; 20]> for [u8; 64] {
    // TODO: Maybe add a checksum address
    fn address_string(&self) -> String {
        let mut result: String = String::from("0x");
        let hex: String = self.keccak256()[12..32].to_hex();
        result.push_str(&hex);
        result
    }

    fn address(&self) -> [u8; 20] {
        let mut result = [0u8; 20];
        result.copy_from_slice(&self.keccak256()[12..32]);
        result
    }
}
