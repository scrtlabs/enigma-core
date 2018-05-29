use tiny_keccak::Keccak;
use secp256k1::{PublicKey, SecretKey, SharedSecret};
use ring::digest;
use ring::aead;
use ring::rand::{SystemRandom, SecureRandom};
use std::string::String;
use std::vec::Vec;

static AES_MODE: &aead::Algorithm = &aead::AES_256_GCM;

pub fn encrypt(message: &Vec<u8>, key: &[u8]) -> Vec<u8> {
    let enc_key = digest::digest(&digest::SHA256, &key);
    let aes_encrypt = aead::SealingKey::new(&AES_MODE, enc_key.as_ref()).unwrap();

    let additional_data: [u8; 0] = [];
    let mut iv: [u8; 12] = [0; 12];
    let r = SystemRandom::new();
    r.fill(&mut iv);

    let mut in_out = message.clone();
    let tag_size = AES_MODE.tag_len();
    for _ in 0..tag_size {
        in_out.push(0);
    }
    let seal_size = aead::seal_in_place(&aes_encrypt, &iv, &additional_data, &mut in_out, tag_size).expect(&"AES encryption failed");
    in_out.append(&mut iv.to_vec());
    println!("{:?}", in_out);
    in_out
}