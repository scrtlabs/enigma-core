
#![cfg_attr(not(feature = "std"), no_std)]
//
//pub mod asymmetric;
pub mod symmetric;
pub mod hashing;
pub mod error;
pub mod rand;

#[cfg(feature = "std")]
use byteorder_std as byteorder;

#[cfg(feature = "sgx")]
use byteorder_sgx as byteorder;

#[cfg(feature = "sgx")]
use sgx_tstd as std;

#[cfg(feature = "std")]
use std;
pub use crate::error::CryptoError;
pub use crate::rand::random;



pub trait Encryption<T, E, R, N>
    where R: Sized, Self: Sized {
    fn encrypt(self, key: T) -> Result<R, E> { self.encrypt_with_nonce(key, None) }
    fn encrypt_with_nonce(self, key: T, _iv: Option<N>) -> Result<R, E>;
    fn decrypt(enc: R, key: T) -> Result<Self, E>;
}


