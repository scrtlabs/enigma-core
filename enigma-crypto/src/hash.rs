//! # Hash Module
//! This module provides Keccak256 and Sha256 implementations as traits for all slices.
//! I think we should consider removing the Sha256 implementation to make sure we use the same hash function always.

use tiny_keccak::Keccak;
use enigma_types::Hash256;


/// Takes a list of variables and concat them together with lengths in between.
/// What this does is appends the length of the messages before each message and makes one big slice from all of them.
/// e.g.: `S(H(len(a)+a, len(b)+b...))`
/// # Examples
/// ```
/// use enigma_crypto::hash;
/// let msg = b"sign";
/// let msg2 = b"this";
/// let ready = hash::prepare_hash_multiple(&[msg, msg2]);
/// ```
#[cfg(any(feature = "sgx", feature = "std"))]
#[allow(unused_imports)]
pub fn prepare_hash_multiple<B: AsRef<[u8]>>(messages: &[B]) -> crate::localstd::vec::Vec<u8> {
    use crate::localstd::{vec::Vec, mem};
    let mut res = Vec::with_capacity(messages.len() * mem::size_of::<usize>());
    for msg in messages {
        let msg = msg.as_ref();
        let len = msg.len().to_be_bytes();
        res.extend_from_slice(&len);
        res.extend_from_slice(&msg);
    }
    res
}

/// A trait that will hash using Keccak256 the object it's implemented on.
pub trait Keccak256<T> {
    /// This will return a sized object with the hash
    fn keccak256(&self) -> T where T: Sized;
}

/// A trait that will hash using Sha256 the object it's implemented on.
pub trait Sha256<T> {
    /// This will return a sized object with the hash
    fn sha256(&self) -> T where T: Sized;
}

impl Keccak256<Hash256> for [u8] {
    fn keccak256(&self) -> Hash256 {
        let mut keccak = Keccak::new_keccak256();
        let mut result = Hash256::default();
        keccak.update(self);
        keccak.finalize(result.as_mut());
        result
    }
}

impl Sha256<Hash256> for [u8] {
    fn sha256(&self) -> Hash256 {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.input(&self);
        let mut result = Hash256::default();
        result.copy_from_slice(&hasher.result());
        result
    }
}
