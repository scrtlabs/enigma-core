use secp256k1;
use secp256k1::{PublicKey, SecretKey, SharedSecret};
use tiny_keccak::Keccak;
use sgx_trts::trts::rsgx_read_rand;
use std::string::String;
use common::utils_t::{ToHex, FromHex, Keccak256};

use std::str;
use std::vec::Vec;

#[derive(Debug)]
pub struct KeyPair {
    pub pubkey: PublicKey,
    pub privkey: SecretKey
}

impl KeyPair {
    pub fn new() -> KeyPair {
        let mut me: [u8; 32] = [0; 32];
        rsgx_read_rand(&mut me);
        let _priv = SecretKey::parse(&me).unwrap();
        let _pub = PublicKey::from_secret_key(&_priv);
        let keys = KeyPair{privkey: _priv, pubkey: _pub};
        keys
    }

    pub fn from_slice(privkey: &[u8; 32]) -> KeyPair {
        let _priv = SecretKey::parse(&privkey).unwrap();
        let _pub = PublicKey::from_secret_key(&_priv);
        let keys = KeyPair{privkey: _priv, pubkey: _pub};
        keys
    }

    pub fn get_aes_key(&self, pubk: &PublicKey) -> Vec<u8> {
        let shared = SharedSecret::new(&pubk, &self.privkey).unwrap();
        let sharedkey = shared.as_ref().to_vec();
        sharedkey
    }

    /// Sign a message using the Private Key.
    /// # Examples
    /// Simple Message signing:
    /// ```
    /// let keys = cryptography::assymetric::KeyPair::new();
    /// let msg = b"Sign this";
    /// let sig = keys.sign(&msg);
    /// ```
    ///
    /// The function returns a 65 bytes slice that contains:
    /// 1. 32 Bytes, ECDSA `r` variable.
    /// 2. 32 Bytes ECDSA `s` variable.
    /// 3. 1 Bytes ECDSA `v` variable aligned to the right for Ethereum compatibility
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let hashed_msg = message.keccak256();
        println!("the hash in hex: {:?}", &hashed_msg.to_hex());
        println!("the hash in array: {:?}", &hashed_msg);
        let message_to_sign = secp256k1::Message::parse(&hashed_msg);
        let result = secp256k1::sign(&message_to_sign, &self.privkey);
        let (sig, recovery) = result.unwrap();
        let v: u8 = recovery.into();

        let mut returnvalue = sig.serialize().to_vec();
        returnvalue.push(v + 27);
        returnvalue
    }
}

pub mod tests {
    extern crate sgx_tunittest;
    use cryptography::assymetric::*;

    pub fn test_signing() {
        let _priv: [u8; 32] = [205, 189, 133, 79, 16, 70, 59, 246, 123, 227, 66, 64, 244, 188, 188, 147, 233, 252, 213, 133, 44, 157, 173, 141, 50, 93, 40, 130, 44, 99, 43, 205];
        let k1 = KeyPair::from_slice(&_priv);
        let msg = b"EnigmaMPC";
        let sig = k1.sign(msg);
        assert_eq!(sig, [103, 116, 208, 210, 194, 35, 190, 81, 174, 162, 1, 162, 96, 104, 170, 243, 216, 2, 241, 93, 149, 208, 46, 210, 136, 182, 93, 63, 178, 161, 75, 139, 3, 16, 162, 137, 184, 131, 214, 175, 49, 11, 54, 137, 232, 88, 234, 75, 2, 103, 33, 244, 158, 81, 162, 241, 31, 158, 136, 30, 38, 191, 124, 93, 28].to_vec());


    }
}