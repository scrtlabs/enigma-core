use crate::localstd::string::String;
use enigma_crypto::hash::Keccak256;
use rustc_hex::ToHex;

#[cfg(feature = "sgx")]
use crate::localstd::sync::{SgxMutex as Mutex, SgxMutexGuard as MutexGuard};

#[cfg(feature = "std")]
use crate::localstd::sync::{Mutex, MutexGuard};


pub trait LockExpectMutex<T> {
    fn lock_expect(&self, name: &str) -> MutexGuard<T>;
}

impl<T> LockExpectMutex<T> for Mutex<T> {
    fn lock_expect(&self, name: &str) -> MutexGuard<T> { self.lock().unwrap_or_else(|_| panic!("{} mutex is poison", name)) }
}

pub trait EthereumAddress<T, P> {
    fn address_string(&self) -> T
    where T: Sized;
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
