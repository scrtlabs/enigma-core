//! # Asymmetric Cryptography.
//! This module provides an interface to generate Secp256k1 keys, sign and verify signatures. <br>
//! Right now we use https://github.com/sorpaas/libsecp256k1-rs as a backend but this is a less common library,
//! Meaning if we use this in testnet/mainnet we should audit that library ourself.
//! otherwise we need to put effort into using the much audited library: https://github.com/bitcoin-core/secp256k1
//! I put work into making the rust bindings for this library support SGX and after this PR it should be ready:
//! https://github.com/rust-bitcoin/rust-secp256k1/pull/115
//! After this PR I think it would be possible to swap that library in instead of the current one.
//!
//! Here is a PoC of how it can be done easily (and the one problem with it) https://github.com/enigmampc/enigma-core/pull/167

use crate::error::CryptoError;
use secp256k1::{PublicKey, SecretKey, SharedSecret,  RecoveryId, Signature};
use crate::hash::Keccak256;
use enigma_types::{DhKey, PubKey};


/// The `KeyPair` struct is used to hold a Private and Public keys.
/// you can use it to sign a message, to derive shared secrets(ECDH) etc.
#[derive(Debug)]
pub struct KeyPair {
    pubkey: PublicKey,
    privkey: SecretKey,
}

impl KeyPair {
    /// This will generate a fresh pair of Public and Private keys.
    /// it will use the available randomness from [crate::rand]
    #[cfg(any(feature = "sgx", feature = "std"))]
    pub fn new() -> Result<KeyPair, CryptoError> {
        use crate::rand;
        // This loop is important to make sure that the resulting public key isn't a point in infinity(at the curve).
        // So if the Resulting public key is bad we need to generate a new random private key and try again until it succeeds.
        loop {
            let mut me: [u8; 32] = [0; 32];
            rand::random(&mut me)?;
            if let Ok(privkey) = SecretKey::parse(&me) {
                let pubkey = PublicKey::from_secret_key(&privkey);
                return Ok(KeyPair { privkey, pubkey });
            }
        }
    }

    /// This function will create a Pair of keys from an array of 32 bytes.
    /// Please don't use it to generate a new key, if you want a new key use `KeyPair::new()`
    /// Because `KeyPair::new()` will make sure it uses a good random source and will loop private keys until it's a good key.
    /// (and it's best to isolate the generation of keys to one place)
    pub fn from_slice(privkey: &[u8; 32]) -> Result<KeyPair, CryptoError> {
        let privkey = SecretKey::parse(&privkey)
            .map_err(|e| CryptoError::KeyError { key_type: "Private Key", err: Some(e) })?;
        let pubkey = PublicKey::from_secret_key(&privkey);

        Ok(KeyPair { privkey, pubkey })
    }

    /// This function does an ECDH(point multiplication) between one's private key and the other one's public key.
    ///
    pub fn derive_key(&self, _pubarr: &PubKey) -> Result<DhKey, CryptoError> {
        let mut pubarr: [u8; 65] = [0; 65];
        pubarr[0] = 4;
        pubarr[1..].copy_from_slice(&_pubarr[..]);

        let pubkey = PublicKey::parse(&pubarr)
            .map_err(|e| CryptoError::KeyError { key_type: "Private Key", err: Some(e) })?;

        let shared = SharedSecret::new(&pubkey, &self.privkey)
            .map_err(|_| CryptoError::DerivingKeyError { self_key: self.get_pubkey(), other_key: *_pubarr })?;

        let mut result = [0u8; 32];
        result.copy_from_slice(shared.as_ref());
        Ok(result)
    }

    /// This will return the raw 32 bytes private key. use carefully.
    pub fn get_privkey(&self) -> [u8; 32] { self.privkey.serialize() }

    /// Get the Public Key and slice the first byte
    /// The first byte represents if the key is compressed or not.
    /// Because we use uncompressed Keys That start with `0x04` we can slice it out.
    ///
    /// We should move to compressed keys in the future, this will save 31 bytes on each pubkey.
    ///
    /// See More:
    ///     `https://tools.ietf.org/html/rfc5480#section-2.2`
    ///     `https://docs.rs/libsecp256k1/0.1.13/src/secp256k1/lib.rs.html#146`
    pub fn get_pubkey(&self) -> PubKey {
        KeyPair::pubkey_object_to_pubkey(&self.pubkey)
    }

    fn pubkey_object_to_pubkey(key: &PublicKey) -> PubKey {
        let mut sliced_pubkey: [u8; 64] = [0; 64];
        sliced_pubkey.clone_from_slice(&key.serialize()[1..65]);
        sliced_pubkey
    }

    /// Sign a message using the Private Key.
    /// # Examples
    /// Simple Message signing:
    /// ```
    /// use enigma_crypto::KeyPair;
    /// let keys = KeyPair::new().unwrap();
    /// let msg = b"Sign this";
    /// let sig = keys.sign(msg);
    /// ```
    ///
    /// The function returns a 65 bytes slice that contains:
    /// 1. 32 Bytes, ECDSA `r` variable.
    /// 2. 32 Bytes ECDSA `s` variable.
    /// 3. 1 Bytes ECDSA `v` variable aligned to the right for Ethereum compatibility
    ///
    /// The `v` variable or so called `Recovery ID` is to tell you if the public key that's needed to verify is even or odd. <br>
    /// Ususally that byte is just 0/1 for some reasons these are represented as 0/1 so we just add 27 to it.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 65], CryptoError> {
        self.sign_hashed(&message.keccak256().into())
    }

    /// Interface for usage without forcing a keccak hash of the input. However, the input must be 32 bytes long.
    /// Mainly useful for when the data is created already hashed and we just want to sign it
    pub fn sign_hashed(&self, message: &[u8; 32]) -> Result<[u8; 65], CryptoError> {
        let message_to_sign = secp256k1::Message::parse(message);

        let (sig, recovery) = secp256k1::sign(&message_to_sign, &self.privkey)
            .map_err(|_| CryptoError::SigningError { hashed_msg: *message })?;

        let v: u8 = recovery.into();
        let mut returnvalue = [0u8; 65];
        returnvalue[..64].copy_from_slice(&sig.serialize());
        returnvalue[64] = v + 27;
        Ok(returnvalue)
    }

    /// Recover the pubkey using the message and it's signature.
    /// # Examples
    /// Simple Message recovering:
    /// ```
    /// use enigma_crypto::KeyPair;
    /// let keys = KeyPair::new().unwrap();
    /// let msg = b"Sign this";
    /// let sig = keys.sign(msg).unwrap();
    /// let recovered_pubkey = KeyPair::recover(msg, sig).unwrap();
    /// ```
    pub fn recover(message: &[u8], sig: [u8;65]) -> Result<[u8; 64], CryptoError> {
        let recovery = RecoveryId::parse(sig[64] -27)
            .map_err(|_| CryptoError::ParsingError { sig })?;
        let signature = Signature::parse_slice(&sig[..64])
            .map_err(|_| CryptoError::ParsingError { sig } )?;
        let hashed_msg = message.keccak256();

        let signed_message = secp256k1::Message::parse(&hashed_msg);
        let recovered_pub = secp256k1::recover(&signed_message, &signature, &recovery)
            .map_err(|_| CryptoError::RecoveryError { sig } )?;

        Ok(KeyPair::pubkey_object_to_pubkey(&recovered_pub))
    }

    /// The same as sign() but for multiple arguments.
    /// What this does is appends the length of the messages before each message and make one big slice from all of them.
    /// e.g.: `S(H(len(a)+a, len(b)+b...))`
    /// # Examples
    /// ```
    /// use enigma_crypto::KeyPair;
    /// let keys = KeyPair::new().unwrap();
    /// let msg = b"sign";
    /// let msg2 = b"this";
    /// let sig = keys.sign_multiple(&[msg, msg2]).unwrap();
    /// ```
    #[cfg(any(feature = "sgx", feature = "std"))]
    pub fn sign_multiple<B: AsRef<[u8]>>(&self, messages: &[B]) -> Result<[u8; 65], CryptoError> {
        let ready = crate::hash::prepare_hash_multiple(messages);
        self.sign(&ready)
    }
}

#[cfg(test)]
mod tests {
    use super::KeyPair;

    #[test]
    fn test_signing() {
        let _priv: [u8; 32] = [205, 189, 133, 79, 16, 70, 59, 246, 123, 227, 66, 64, 244, 188, 188, 147, 233, 252, 213, 133, 44, 157, 173, 141, 50, 93, 40, 130, 44, 99, 43, 205];
        let k1 = KeyPair::from_slice(&_priv).unwrap();
        let msg = b"EnigmaMPC";
        let sig = k1.sign(msg).unwrap();
        assert_eq!(
            sig.to_vec(),
            vec![103, 116, 208, 210, 194, 35, 190, 81, 174, 162, 1, 162, 96, 104, 170, 243, 216, 2, 241, 93, 149, 208, 46, 210, 136, 182, 93, 63, 178, 161, 75, 139, 3, 16, 162, 137, 184, 131, 214, 175, 49, 11, 54, 137, 232, 88, 234, 75, 2, 103, 33, 244, 158, 81, 162, 241, 31, 158, 136, 30, 38, 191, 124, 93, 28]
        );
    }

    #[test]
    fn test_recover() {
        let _priv: [u8; 32] = [205, 189, 133, 79, 16, 70, 59, 246, 123, 227, 66, 64, 244, 188, 188, 147, 233, 252, 213, 133, 44, 157, 173, 141, 50, 93, 40, 130, 44, 99, 43, 205];
        let k1 = KeyPair::new().unwrap();
        let msg = b"EnigmaMPC";
        let sig = k1.sign(msg).unwrap();
        let recover_pub = KeyPair::recover(msg, sig).unwrap();
        assert_eq!(&k1.get_pubkey()[..], &recover_pub[..]);
    }

    #[test]
    fn test_ecdh() {
        let _priv1: [u8; 32] = [205, 189, 133, 79, 16, 70, 59, 246, 123, 227, 66, 64, 244, 188, 188, 147, 233, 252, 213, 133, 44, 157, 173, 141, 50, 93, 40, 130, 44, 99, 43, 205];
        let _priv2: [u8; 32] = [181, 71, 210, 141, 65, 214, 242, 119, 127, 212, 100, 4, 19, 131, 252, 56, 173, 224, 167, 158, 196, 65, 19, 33, 251, 198, 129, 58, 247, 127, 88, 162];
        let k1 = KeyPair::from_slice(&_priv1).unwrap();
        let k2 = KeyPair::from_slice(&_priv2).unwrap();
        let shared1 = k1.derive_key(&k2.get_pubkey()).unwrap();
        let shared2 = k2.derive_key(&k1.get_pubkey()).unwrap();
        assert_eq!(shared1, shared2);
        assert_eq!(
            shared1,
            [139, 184, 212, 39, 0, 146, 97, 243, 63, 65, 81, 130, 96, 208, 43, 150, 229, 90, 132, 202, 235, 168, 86, 59, 141, 19, 200, 38, 242, 55, 203, 15]
        );
    }
}
