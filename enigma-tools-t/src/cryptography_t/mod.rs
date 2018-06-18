pub mod asymmetric;
pub mod symmetric;

use storage_t;
use std::untrusted::fs::{File, remove_file};
use std::io::{Read, ErrorKind};


pub fn get_sealed_keys(sealed_path: &str) -> asymmetric::KeyPair {
    // Open the file
    match File::open(sealed_path) {
        Ok(mut file) => {
            let mut sealed:[u8; storage_t::SEAL_LOG_SIZE] = [0; storage_t::SEAL_LOG_SIZE];
            file.read(&mut sealed);
            match storage_t::SecretKeyStorage::unseal_key(&mut sealed) {
                // If the data is unsealed correctly return this KeyPair.
                Some(unsealed_data) => {
                    println!("Succeeded reading key from file");
                    return asymmetric::KeyPair::from_slice(&unsealed_data.data);
                },
                // If the data couldn't get unsealed remove the file.
                None => {
                    println!("Failed reading file, Removing");
                    remove_file(sealed_path)
                }
            };
        },
        Err(err) => {
            if err.kind() == ErrorKind::PermissionDenied { panic!("No Permissions for: {}", sealed_path) }
        }
    }

    // Generate a new Keypair and seal it.
    let keypair = asymmetric::KeyPair::new();
    let data = storage_t::SecretKeyStorage {version: 0x1, data: keypair.get_privkey()};
    let mut output: [u8; storage_t::SEAL_LOG_SIZE] = [0; storage_t::SEAL_LOG_SIZE];
    data.seal_key(&mut output);
    storage_t::save_sealed_key(&sealed_path, &output);
    println!("Generated a new key");

    keypair
}