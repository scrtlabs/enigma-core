use crate::CryptoError;
use crate::localstd::format;

#[cfg(all(feature = "std", not(feature = "sgx")))]
pub fn random(rand: &mut [u8]) -> Result<(), CryptoError> {
    use rand_std::{Rng, rngs::EntropyRng};
    let mut rng = EntropyRng::new();
    rng.try_fill(rand)
        .map_err(|e| CryptoError::RandomError { err: format!("{:?}", e) } )
}


#[cfg(all(feature = "sgx", not(feature = "std")))]
pub fn random(rand: &mut [u8]) -> Result<(), CryptoError> {
    use sgx_trts::trts::rsgx_read_rand;
    rsgx_read_rand(rand)
        .map_err(|e| CryptoError::RandomError { err: format!("{:?}", e) } )
}