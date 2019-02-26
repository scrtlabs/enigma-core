#![feature(int_to_from_bytes)]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![deny(unused_extern_crates)]

#[cfg(feature = "asymmetric")]
pub mod asymmetric;
#[cfg(feature = "hash")]
pub mod hash;
pub mod error;
pub mod rand;

#[cfg(feature = "symmetric")]
pub mod symmetric;

#[cfg(feature = "sgx")]
use {
    sgx_tstd as localstd,
};


#[cfg(feature = "std")]
use {
    std as localstd,
};

pub use crate::error::CryptoError;

#[cfg(feature = "asymmetric")]
pub use crate::asymmetric::KeyPair;


pub trait Encryption<T, E, R, N>
    where R: Sized, Self: Sized {
    fn encrypt(self, key: T) -> Result<R, E> { self.encrypt_with_nonce(key, None) }
    fn encrypt_with_nonce(self, key: T, _iv: Option<N>) -> Result<R, E>;
    fn decrypt(enc: R, key: T) -> Result<Self, E>;
}

