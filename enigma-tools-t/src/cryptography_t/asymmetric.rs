use secp256k1;
use secp256k1::{PublicKey, SecretKey, SharedSecret};
use tiny_keccak::Keccak;
use sgx_trts::trts::rsgx_read_rand;
use std::string::String;
use common::utils_t::{ToHex, FromHex, Keccak256};

use std::str;
use std::vec::Vec;
use std::str::from_utf8;

#[derive(Debug)]
pub struct KeyPair {
    pub pubkey: PublicKey,
    pub privkey: SecretKey
}

impl KeyPair {
    pub fn new() -> KeyPair {
        let mut me: [u8; 32] = [0; 32];
        // TODO: Check if needs to check the random is within the curve.
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
        // TODO: Maybe accept a slice [u8; 64] and add 0x04, and then make the PublicKey obj.
        let shared = SharedSecret::new(&pubk, &self.privkey).unwrap();
        let sharedkey = shared.as_ref().to_vec();
        sharedkey
    }
    pub fn get_privkey(&self) -> [u8; 32] {
        self.privkey.serialize()
    }

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
        *&sliced_pubkey
    }

    /// Sign a message using the Private Key.
    /// # Examples
    /// Simple Message signing:
    /// ```
    /// let keys = cryptography_t::asymmetric::KeyPair::new();
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
    use cryptography_t::asymmetric::*;

    pub fn test_signing() {
        let _priv: [u8; 32] = [205, 189, 133, 79, 16, 70, 59, 246, 123, 227, 66, 64, 244, 188, 188, 147, 233, 252, 213, 133, 44, 157, 173, 141, 50, 93, 40, 130, 44, 99, 43, 205];
        let k1 = KeyPair::from_slice(&_priv);
        let msg = b"EnigmaMPC";
        let sig = k1.sign(msg);
        println!("Message: {:?}, Signature: {:?}", from_utf8(msg), &sig.to_hex());
        assert_eq!(sig, [103, 116, 208, 210, 194, 35, 190, 81, 174, 162, 1, 162, 96, 104, 170, 243, 216, 2, 241, 93, 149, 208, 46, 210, 136, 182, 93, 63, 178, 161, 75, 139, 3, 16, 162, 137, 184, 131, 214, 175, 49, 11, 54, 137, 232, 88, 234, 75, 2, 103, 33, 244, 158, 81, 162, 241, 31, 158, 136, 30, 38, 191, 124, 93, 28].to_vec());
    }

    pub fn test_ecdh() {
        let _priv1: [u8; 32] = [205, 189, 133, 79, 16, 70, 59, 246, 123, 227, 66, 64, 244, 188, 188, 147, 233, 252, 213, 133, 44, 157, 173, 141, 50, 93, 40, 130, 44, 99, 43, 205];
        let _priv2: [u8; 32] = [181, 71, 210, 141, 65, 214, 242, 119, 127, 212, 100, 4, 19, 131, 252, 56, 173, 224, 167, 158, 196, 65, 19, 33, 251, 198, 129, 58, 247, 127, 88, 162];
        let k1 = KeyPair::from_slice(&_priv1);
        let k2 = KeyPair::from_slice(&_priv2);
        let shared1 = k1.get_aes_key(&k2.pubkey);
        let shared2 = k2.get_aes_key(&k1.pubkey);
        println!("the Derived key: {:?}, Hex: {:?}", &shared1, &shared1.to_hex());
        assert_eq!(shared1, shared2);
        assert_eq!(shared1, [139, 184, 212, 39, 0, 146, 97, 243, 63, 65, 81, 130, 96, 208, 43, 150, 229, 90, 132, 202, 235, 168, 86, 59, 141, 19, 200, 38, 242, 55, 203, 15]);
    }
}