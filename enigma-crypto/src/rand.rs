//! # Rand module
//! This module is an abstraction layer over the random functions. <br>
//! The purpose of it is so it can be used the same within and outside of SGX
//! (through `/dev/urandom` and through the `RDRAND` instruction.)


#[cfg(all(feature = "std", not(feature = "sgx")))]
/// This function gets a mutable slice and will fill it
/// with random data using the available randomness source
pub fn random(rand: &mut [u8]) -> Result<(), crate::CryptoError> {
    use rand_std::{Rng, rngs::EntropyRng};
    let mut rng = EntropyRng::new();
    rng.try_fill(rand)
        .map_err(|e| crate::CryptoError::RandomError { err: e } )
}

#[cfg(all(feature = "sgx", not(feature = "std")))]
/// This function gets a mutable slice and will fill it
/// with random data using the available randomness source
pub fn random(rand: &mut [u8]) -> Result<(), crate::CryptoError> {
    use sgx_trts::trts::rsgx_read_rand;
    rsgx_read_rand(rand)
        .map_err(|e| crate::CryptoError::RandomError { err: e } )
}