use common::errors_t::EnclaveError;
use common::utils_t::ToHex;
use ring::aead;
use sgx_trts::trts::rsgx_read_rand;
use std::borrow::ToOwned;
use std::option::Option;
use std::string::ToString;
use std::vec::Vec;

static AES_MODE: &aead::Algorithm = &aead::AES_256_GCM;
type Key = [u8; 32];
type IV = [u8; 12];

pub fn encrypt(message: &[u8], key: &Key) -> Result<Vec<u8>, EnclaveError> { encrypt_with_nonce(message, key, None) }

pub fn encrypt_with_nonce(message: &[u8], key: &Key, _iv: Option<IV>) -> Result<Vec<u8>, EnclaveError> {
    let iv: [u8; 12] = match _iv {
        Some(x) => x,
        None => {
            let mut _tmp_iv = [0; 12];
            rsgx_read_rand(&mut _tmp_iv)?;
            _tmp_iv
        }
    };
    let additional_data: [u8; 0] = [];

    let aes_encrypt = match aead::SealingKey::new(&AES_MODE, key) {
        Ok(key) => key,
        Err(_) => return Err(EnclaveError::KeyError { key: "".to_string(), key_type: "Encryption".to_string() }),
    };
    let mut in_out = message.to_owned();
    let tag_size = AES_MODE.tag_len();
    for _ in 0..tag_size {
        in_out.push(0);
    }
    let seal_size = match aead::seal_in_place(&aes_encrypt, &iv, &additional_data, &mut in_out, tag_size) {
        Ok(size) => size,
        Err(_) => return Err(EnclaveError::EncryptionError {}),
    };
    //    println!("**Returned size: {:?}, Real size: {:?}", &seal_size, in_out.len());
    let mut in_out = in_out[..seal_size].to_vec();
    in_out.append(&mut iv.to_vec());
    Ok(in_out)
}

pub fn decrypt(cipheriv: &[u8], key: &Key) -> Result<Vec<u8>, EnclaveError> {
    let aes_decrypt = match aead::OpeningKey::new(&AES_MODE, key) {
        Ok(key) => key,
        Err(_) => return Err(EnclaveError::KeyError { key: "".to_string(), key_type: "Encryption".to_string() }),
    };
    let additional_data: [u8; 0] = [];
    let mut ciphertext = cipheriv.to_owned();
    let mut iv: [u8; 12] = [0; 12];
    for _i in (0..iv.len()).rev() {
        match ciphertext.pop() {
            Some(v) => iv[_i] = v,
            None => return Err(EnclaveError::DecryptionError { encrypted_parm: "Improper encryption".to_string() }),
        };
    }
    let decrypted_data = match aead::open_in_place(&aes_decrypt, &iv, &additional_data, 0, &mut ciphertext) {
        Ok(data) => data,
        Err(_) => return Err(EnclaveError::DecryptionError { encrypted_parm: cipheriv.to_hex() }),
    };

    Ok(decrypted_data.to_vec())
}

pub mod tests {
    use common::utils_t::{FromHex, Sha256, ToHex};
    use cryptography_t::symmetric::*;
    use sgx_trts::trts::rsgx_read_rand;
    use build_arguments_g::get_key;

    pub fn test_rand_encrypt_decrypt() {
        let mut rand_seed: [u8; 1072] = [0; 1072];
        rsgx_read_rand(&mut rand_seed).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&rand_seed[..32]);
        let mut iv: [u8; 12] = [0; 12];
        iv.clone_from_slice(&rand_seed[32..44]);
        let msg = rand_seed[44..1068].to_vec();
        let ciphertext = encrypt_with_nonce(&msg, &key, Some(iv)).unwrap();
        assert_eq!(msg, decrypt(&ciphertext, &key).unwrap());
    }

    pub fn test_encryption() {
        let key = b"EnigmaMPC".sha256();
        let msg = b"This Is Enigma".to_vec();
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let result = encrypt_with_nonce(&msg, &key, Some(iv)).unwrap();
        assert_eq!(result.to_hex(), "02dc75395859faa78a598e11945c7165db9a16d16ada1b026c9434b134ae000102030405060708090a0b");
    }

    pub fn test_decryption() {
        let encrypted_data = "02dc75395859faa78a598e11945c7165db9a16d16ada1b026c9434b134ae000102030405060708090a0b";
        let key = b"EnigmaMPC".sha256();
        let result = decrypt(&encrypted_data.from_hex().unwrap(), &key).unwrap();
        assert_eq!(result, b"This Is Enigma".to_vec());

//        // for encryption purposes:
//        // use ethabi-cli to encode params then put the result in msg and get the encrypted arguments.
//        let key = get_key();
//        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
//        let msg = "0000000000000000000000005ed8cee6b63b1c6afce3ad7c92f4fd7e1b8fad9f".from_hex().unwrap();
//        let enc = encrypt_with_nonce(&msg, &key, Some(iv)).unwrap();

    }
}
