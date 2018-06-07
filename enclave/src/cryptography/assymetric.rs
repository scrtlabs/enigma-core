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
        let v: u8 = recovery.into() + 27;

        let mut returnvalue = sig.serialize().to_vec();
        returnvalue.push(v);
        println!("{:?}", &returnvalue[..]);
        returnvalue
    }

}