use ring::aead;
use ring::rand::{SystemRandom, SecureRandom};
use std::vec::Vec;
use std::string::ToString;
use std::option::Option;
use common::utils_t::ToHex;
use common::errors_t::EnclaveError;

static AES_MODE: &aead::Algorithm = &aead::AES_256_GCM;

//TODO:: error handling return a result/match
pub fn encrypt(message: &Vec<u8>, key: &[u8], _iv: &Option<[u8; 12]>) -> Vec<u8> {
    let mut iv: [u8; 12];
    match _iv {
        Some(x) => {iv = *x;},
        None => {
            iv = [0; 12];
            let r = SystemRandom::new();
            match r.fill(&mut iv){
                Ok(_v)=>{},
                Err(_e)=>{},
            };
        }
    }
    let additional_data: [u8; 0] = [];

    let aes_encrypt = aead::SealingKey::new(&AES_MODE, key).unwrap();

    let mut in_out = message.clone();
    let tag_size = AES_MODE.tag_len();
    for _ in 0..tag_size {
        in_out.push(0);
    }
    let seal_size = aead::seal_in_place(&aes_encrypt, &iv, &additional_data, &mut in_out, tag_size).expect(&"AES encryption failed");
    println!("**Returned size: {:?}, Real size: {:?}", &seal_size, in_out.len());
    in_out.append(&mut iv.to_vec());
    in_out
}

pub fn decrypt(cipheriv: &Vec<u8>, key: &[u8]) -> Result<Vec<u8>, EnclaveError> {
    let aes_decrypt = match aead::OpeningKey::new(&AES_MODE, key) {
        Ok(key) => key,
        Err(_) => return Err(EnclaveError::KeyErr{key: "".to_string(), key_type: "Encryption".to_string()})
    };
    let additional_data: [u8; 0] = [];
    let mut ciphertext = cipheriv.clone();
    let mut iv: [u8; 12] = [0; 12];
    for _i in (0..iv.len()).rev() {
        iv[_i] = ciphertext.pop().unwrap();
    }
    let decrypted_data = match aead::open_in_place(&aes_decrypt, &iv, &additional_data, 0, &mut ciphertext) {
        Ok(data) => data,
        Err(_) => return Err(EnclaveError::DecryptionError{encrypted_parm: cipheriv.as_slice().to_hex()})
    };

    Ok(decrypted_data.to_vec())
}

pub mod tests {
    use ring::digest;
    use cryptography_t::symmetric::*;
    use common::utils_t::{ToHex, FromHex};
    use sgx_trts::trts::rsgx_read_rand;

    pub fn test_rand_encrypt_decrypt() {
        let mut rand_seed: [u8; 1072] = [0; 1072];
        rsgx_read_rand(&mut rand_seed).unwrap();
        let key = &rand_seed[..32];
        let mut iv: [u8; 12] = [0; 12];
        iv.clone_from_slice(&rand_seed[32..44]);
        let msg = rand_seed[44..1068].to_vec();
        let ciphertext = encrypt(&msg, key, &Some(iv));
        assert_eq!(msg, decrypt(&ciphertext, &key).unwrap());
    }

    pub fn test_encryption() {
        let key = digest::digest(&digest::SHA256, b"EnigmaMPC");
        let msg = b"This Is Enigma".to_vec();
        let iv = Some( [0,1,2,3,4,5,6,7,8,9,10,11] );
        let result = encrypt(&msg, key.as_ref(), &iv);
//        println!("{:?}", result.to_hex());
        assert_eq!(result.to_hex(), "02dc75395859faa78a598e11945c7165db9a16d16ada1b026c9434b134ae000102030405060708090a0b");

    }

    pub fn test_decryption() {
        let encrypted_data = "02dc75395859faa78a598e11945c7165db9a16d16ada1b026c9434b134ae000102030405060708090a0b";
        let key = digest::digest(&digest::SHA256, b"EnigmaMPC");
        let result = decrypt(&encrypted_data.from_hex().unwrap(), key.as_ref()).unwrap();
        assert_eq!(result, b"This Is Enigma".to_vec());
    }
}