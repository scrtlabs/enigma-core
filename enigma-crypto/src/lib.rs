#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![deny(unused_extern_crates, missing_docs, warnings)]
//! # Enigma Crypto
//! This library is a wrapper for all of our cryptographic needs. <br>
//! No crypto (encryption/hashing/signing etc.) should be used directly. everything should go through this library. <br>
//! This library can work on both sides of the SGX through the use of compilation cfg's. <br>
//! It also works in  WASM, but without the symmetric encryption, because `ring` uses AES-NI instructions which are x86(64) only. <br>
//!
//! Inside of this library I abstracted the std as `localstd` so that you can use it without knowing if it's `sgx_tstd` or regular std.
//!
//! This crate is Rust 2018 Edition,
//! meaning there's no `extern crate` and `use` statements need to start with `crate`/`self`/`super`.

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

#[cfg(all(not(feature = "std"), not(feature = "sgx")))]
extern crate core as localstd;

pub use crate::error::CryptoError;

#[cfg(feature = "asymmetric")]
pub use crate::asymmetric::KeyPair;



/// This trait is to encrypt/decrypt a struct, when implemented you should use `symmetric::encrypt`.
/// when you implement decrypt and encrypt_with_nonce you get `encrypt` for free(don't need to implement manually).
/// you should only use decrypt/encrypt. `encrypt_with_nonce` is for testing purposes only.
pub trait Encryption<T, E, R, N>
    where R: Sized, Self: Sized {
    /// the `encrypt` function is given for free
    #[allow(deprecated)]
    fn encrypt(self, key: T) -> Result<R, E> { self.encrypt_with_nonce(key, None) }
    #[deprecated(note = "This function shouldn't be called directly, please use `encrypt()` instead")]
    /// This function is to encrypt the object using the given key. it shouldn't be used directly.
    /// It should only be implemented in order for you to get the normal `encrypt` function.
    fn encrypt_with_nonce(self, key: T, _iv: Option<N>) -> Result<R, E>;
    /// This function will decrypt the encrypted struct using `encrypt` into the same object.
    fn decrypt(enc: R, key: T) -> Result<Self, E>;
}

/// This trait is used for structures that can implement an ECDSA signing. Used to allow abstraction
/// of the actual signer of the data
pub trait EcdsaSign {
    /// This function is used to sign pre-hashed data (keccak256, or other 32-byte length hashes)
    fn sign_hashed(&self, to_sign: &[u8; 32]) -> [u8; 65];
}
