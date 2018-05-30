use secp256k1;
use secp256k1::{PublicKey, SecretKey, SharedSecret};
use tiny_keccak::Keccak;
use sgx_trts::trts::rsgx_read_rand;
use std::string::String;

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

    pub fn get_aes_key(&self, pubk: &PublicKey) -> [u8; 32] {
        let shared = SharedSecret::new(&pubk, &self.privkey).unwrap();
        let mut sharedkey: [u8;32] = [0;32];
        for i in 0..shared.as_ref().len()-1 {
            sharedkey[i] = shared.as_ref()[i];
        }
        sharedkey
    }

    pub fn sign(&self, message: &[u8]) -> (secp256k1::Signature, secp256k1::RecoveryId) {
        let mut keccak256 = Keccak::new_sha3_256();
        keccak256.update(&message);
        let mut hashresult: [u8; 32]= [0; 32];
        keccak256.finalize(&mut hashresult);
        let message_to_sign = secp256k1::Message::parse(&hashresult);
        let result = secp256k1::sign(&message_to_sign, &self.privkey);
        result.unwrap()
    }

}