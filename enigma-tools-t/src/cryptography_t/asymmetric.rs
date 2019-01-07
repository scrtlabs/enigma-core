use crate::common::{utils_t::{Keccak256, ToHex}, errors_t::EnclaveError};
use secp256k1::{PublicKey, SecretKey, SharedSecret, self};
use sgx_trts::trts::rsgx_read_rand;
use std::{string::ToString, vec::Vec, mem};
use byteorder::{BigEndian, ByteOrder};

#[derive(Debug)]
pub struct KeyPair {
    pubkey: PublicKey,
    privkey: SecretKey,
}

impl KeyPair {
    pub fn new() -> Result<KeyPair, EnclaveError> {
        loop {
            let mut me: [u8; 32] = [0; 32];
            rsgx_read_rand(&mut me)?;
            if let Ok(_priv) = SecretKey::parse(&me) { return Ok(KeyPair { privkey: _priv.clone(), pubkey: PublicKey::from_secret_key(&_priv) }) }
        }
    }

    pub fn from_slice(privkey: &[u8; 32]) -> Result<KeyPair, EnclaveError> {
        let _priv = match SecretKey::parse(&privkey) {
            Ok(key) => key,
            Err(_) => return Err(EnclaveError::KeyError { key_type: "Private Key".to_string(), key: "".to_string() }),
        };
        let _pub = PublicKey::from_secret_key(&_priv);
        let keys = KeyPair { privkey: _priv, pubkey: _pub };
        Ok(keys)
    }

    pub fn get_aes_key(&self, _pubarr: &[u8; 64]) -> Result<[u8; 32], EnclaveError> {
        let mut pubarr: [u8; 65] = [0; 65];
        pubarr[0] = 4;
        pubarr[1..].copy_from_slice(&_pubarr[..]);
        let pubkey = match PublicKey::parse(&pubarr) {
            Ok(key) => key,
            Err(_) => return Err(EnclaveError::KeyError { key: _pubarr.to_hex(), key_type: "PublicKey".to_string() }),
        };
        match SharedSecret::new(&pubkey, &self.privkey) {
            Ok(val) => {
                let mut result = [0u8; 32];
                result.copy_from_slice(val.as_ref());
                Ok(result)
            },
            Err(_) => Err(EnclaveError::DerivingKeyError { self_key: self.get_pubkey().to_hex(), other_key: pubkey.serialize()[1..65].to_hex(), }),
        }
    }
    pub fn get_privkey(&self) -> [u8; 32] { self.privkey.serialize() }

    /// Get the Public Key and slice the first byte
    /// The first byte represents if the key is compressed or not.
    /// Because we always use Uncompressed Keys That's start with `0x04` we can slice it out.
    ///
    /// See More:
    ///     `https://tools.ietf.org/html/rfc5480#section-2.2`
    ///     `https://docs.rs/libsecp256k1/0.1.13/src/secp256k1/lib.rs.html#146`
    pub fn get_pubkey(&self) -> [u8; 64] {
        let mut sliced_pubkey: [u8; 64] = [0; 64];
        sliced_pubkey.clone_from_slice(&self.pubkey.serialize()[1..65]);
        sliced_pubkey
    }

    /// Sign a message using the Private Key.
    /// # Examples
    /// Simple Message signing:
    /// ```
    /// let keys = KeyPair::new();
    /// let msg = b"Sign this";
    /// let sig = keys.sign(&msg);
    /// ```
    ///
    /// The function returns a 65 bytes slice that contains:
    /// 1. 32 Bytes, ECDSA `r` variable.
    /// 2. 32 Bytes ECDSA `s` variable.
    /// 3. 1 Bytes ECDSA `v` variable aligned to the right for Ethereum compatibility
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 65], EnclaveError> {
        let hashed_msg = message.keccak256();
        let message_to_sign = secp256k1::Message::parse(&hashed_msg);
        let (sig, recovery) = match secp256k1::sign(&message_to_sign, &self.privkey) {
            Ok((sig, rec)) => (sig, rec),
            Err(_) => return Err(EnclaveError::SigningError { msg: message.to_hex() }),
        };
        let v: u8 = recovery.into();
        let mut returnvalue = [0u8; 65];
        returnvalue[..64].copy_from_slice(&sig.serialize()[..]);
        returnvalue[64] = v + 27;
        Ok(returnvalue)
    }

    /// The same as sign() but for multiple arguments.
    /// What this does is appends the length of the messages before each message and make one big slice from all of them.
    /// e.g.: `S(H(len(a)+a, len(b)+b...))`
    /// # Examples
    /// ```
    /// let keys = KeyPair::new();
    /// let msg = b"sign";
    /// let msg2 = b"this";
    /// let sig = keys.sign_multiple(&[msg, msg2]).unwrap();
    /// ```
    pub fn sign_multiple(&self, messages: &[&[u8]]) -> Result<[u8; 65], EnclaveError> {
        let ready: Vec<_> = messages.into_iter().flat_map(|s| {
            let len = s.len();
            let size = mem::size_of_val(&len);
            let mut tmp = Vec::with_capacity(len + size);
            tmp.extend_from_slice(s);
            BigEndian::write_uint(&mut tmp, len as u64, size);
            tmp
        }).collect();
        self.sign(&ready)
    }
}

pub mod tests {
    use cryptography_t::asymmetric::*;

    pub fn test_signing() {
        let _priv: [u8; 32] = [205, 189, 133, 79, 16, 70, 59, 246, 123, 227, 66, 64, 244, 188, 188, 147, 233, 252, 213, 133, 44, 157, 173, 141, 50, 93, 40, 130, 44, 99, 43, 205];
        let k1 = KeyPair::from_slice(&_priv).unwrap();
        let msg = b"EnigmaMPC";
        let sig = k1.sign(msg).unwrap();
        assert_eq!(sig.to_vec(), [103, 116, 208, 210, 194, 35, 190, 81, 174, 162, 1, 162, 96, 104, 170, 243, 216, 2, 241, 93, 149, 208, 46, 210, 136, 182, 93, 63, 178, 161, 75, 139, 3, 16, 162, 137, 184, 131, 214, 175, 49, 11, 54, 137, 232, 88, 234, 75, 2, 103, 33, 244, 158, 81, 162, 241, 31, 158, 136, 30, 38, 191, 124, 93, 28].to_vec());
    }

    pub fn test_ecdh() {
        let _priv1: [u8; 32] = [205, 189, 133, 79, 16, 70, 59, 246, 123, 227, 66, 64, 244, 188, 188, 147, 233, 252, 213, 133, 44, 157, 173, 141, 50, 93, 40, 130, 44, 99, 43, 205];
        let _priv2: [u8; 32] = [181, 71, 210, 141, 65, 214, 242, 119, 127, 212, 100, 4, 19, 131, 252, 56, 173, 224, 167, 158, 196, 65, 19, 33, 251, 198, 129, 58, 247, 127, 88, 162];
        let k1 = KeyPair::from_slice(&_priv1).unwrap();
        let k2 = KeyPair::from_slice(&_priv2).unwrap();
        let shared1 = k1.get_aes_key(&k2.get_pubkey()).unwrap();
        let shared2 = k2.get_aes_key(&k1.get_pubkey()).unwrap();
        assert_eq!(shared1, shared2);
        assert_eq!(shared1, [139, 184, 212, 39, 0, 146, 97, 243, 63, 65, 81, 130, 96, 208, 43, 150, 229, 90, 132, 202, 235, 168, 86, 59, 141, 19, 200, 38, 242, 55, 203, 15]);

    }
}
