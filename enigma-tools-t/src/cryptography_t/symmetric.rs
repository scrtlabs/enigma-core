use tiny_keccak::Keccak;
use secp256k1::{PublicKey, SecretKey, SharedSecret};
use ring::digest;
use ring::aead;
use ring::rand::{SystemRandom, SecureRandom};
use std::string::String;
use std::vec::Vec;
use std::option::Option;

static AES_MODE: &aead::Algorithm = &aead::AES_256_GCM;

pub fn encrypt(message: &Vec<u8>, key: &[u8], _iv: &Option<[u8; 12]>) -> Vec<u8> {
    let mut iv: [u8; 12];
    match _iv {
        Some(x) => {iv = *x;},
        None => {
            iv = [0; 12];
            let r = SystemRandom::new();
            r.fill(&mut iv);
        }
    }
    let additional_data: [u8; 0] = [];

    let enc_key = digest::digest(&digest::SHA256, &key);
    let aes_encrypt = aead::SealingKey::new(&AES_MODE, enc_key.as_ref()).unwrap();

    let mut in_out = message.clone();
    let tag_size = AES_MODE.tag_len();
    for _ in 0..tag_size {
        in_out.push(0);
    }
    let seal_size = aead::seal_in_place(&aes_encrypt, &iv, &additional_data, &mut in_out, tag_size).expect(&"AES encryption failed");
    in_out.append(&mut iv.to_vec());
    in_out
}

pub fn decrypt(cipheriv: &Vec<u8>, key: &[u8]) -> Vec<u8>{
    let enc_key = digest::digest(&digest::SHA256, &key);
    let aes_decrypt = aead::OpeningKey::new(&AES_MODE, enc_key.as_ref()).unwrap();
    let additional_data: [u8; 0] = [];
    let mut ciphertext = cipheriv.clone();
    let mut iv: [u8; 12] = [0; 12];
    for _i in (0..iv.len()).rev() {
        iv[_i] = ciphertext.pop().unwrap();
    }
    println!("{:?}", iv);
    let decrypted_data = aead::open_in_place(&aes_decrypt, &iv, &additional_data, 0, &mut ciphertext).expect(&"AES decryption failed");
    let result = decrypted_data.to_vec();
    result
}

pub mod tests {
    use cryptography_t::symmetric::*;
    use common::utils_t::{ToHex, FromHex};
    use sgx_trts::trts::rsgx_read_rand;
    use sgx_types::sgx_status_t;

    pub fn test_rand_encrypt_decrypt() {
        let mut rand_seed: [u8; 1072] = [0; 1072];
        rsgx_read_rand(&mut rand_seed).unwrap();
        let key = &rand_seed[..32];
        let mut iv: [u8; 12] = [0; 12];
        iv.clone_from_slice(&rand_seed[32..44]);
        let msg = rand_seed[44..1068].to_vec();
        let ciphertext = encrypt(&msg, key, &Some(iv));
        assert_eq!(msg, decrypt(&ciphertext, &key));
    }

    pub fn test_encryption() {
        let key = b"EnigmaMPC";
        let msg = b"This Is Enigma".to_vec();
        let iv = Some( [0,1,2,3,4,5,6,7,8,9,10,11] );
        let result = encrypt(&msg, key, &iv);
//        println!("{:?}", result.to_hex());
        assert_eq!(result.to_hex(), "02dc75395859faa78a598e11945c7165db9a16d16ada1b026c9434b134ae000102030405060708090a0b");
    }

    pub fn test_decryption() {
        let encrypted_data = "02dc75395859faa78a598e11945c7165db9a16d16ada1b026c9434b134ae000102030405060708090a0b";
        let key = b"EnigmaMPC";
        let result = decrypt(&encrypted_data.from_hex().unwrap(), key);
        assert_eq!(result, b"This Is Enigma".to_vec());
    }
}