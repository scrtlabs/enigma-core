// Rust’s standard library provides a lot of useful functionality, but assumes support for various
// features of its host system: threads, networking, heap allocation, and others. SGX environments
// do not have these features, so we tell Rust that we don’t want to use the standard library
#![no_std]
#![allow(unused_attributes)]

#[macro_use]
extern crate serde_derive;
extern crate serde;
// The eng_wasm crate allows to use the Enigma runtime, which provides:
//     - Read from state      read_state!(key)
//     - Write to state       write_state!(key => value)
//     - Print                eprint!(...)
extern crate eng_wasm;

// The eng_wasm_derive crate provides the following
//     - Functions exposed by the contract that may be called from the Enigma network
//     - Ability to call functions of ethereum contracts from ESC
extern crate eng_wasm_derive;

// The asymmetric features of enigma_crypto
extern crate enigma_crypto;

// Serialization stuff
extern crate rustc_hex;

// eng_wasm
use eng_wasm::*;
use eng_wasm_derive::pub_interface;
use eng_wasm::{String, Vec};
use rustc_hex::ToHex;
use enigma_crypto::asymmetric::KeyPair;

// State key name "mixer_eth_addr" holding eth address of Mixer contract
//static MIXER_ETH_ADDR: &str = "mixer_eth_addr";
static ENCRYPTION_KEY: &str = "encryption_key";

// For contract-exposed functions, declare such functions under the following public trait:
#[pub_interface]
pub trait ContractInterface {
    fn construct();
    fn encrypt_decrypt(plaintext_msg: Vec<u8>);
}

// The implementation of the exported ESC functions should be defined in the trait implementation
// for a new struct.
// #[no_mangle] modifier is required before each function to turn off Rust's name mangling, so that
// it is easier to link to. Sets the symbol for this item to its identifier.
pub struct Contract;

// Private functions accessible only by the secret contract
impl Contract {
    fn get_pkey() -> SymmetricKey {
        let key = read_state!(ENCRYPTION_KEY).unwrap();
        let key_pair = KeyPair::from_slice(&key).unwrap();
        let pub_key = key_pair.get_pubkey();
        eprint!("The pub key from the generated key material({:?})", pub_key.to_vec());
        key
    }

    fn decrypt(enc_msg: &Vec<u8>) -> Vec<u8> {
        let key = Self::get_pkey();
        eprint!("Decrypting bytes ({:?})", enc_msg);
        decrypt(enc_msg, &key)
    }

    fn encrypt(plaintext_msg: &Vec<u8>) -> Vec<u8> {
        let key = Self::get_pkey();
        eprint!("Encrypting bytes ({:?})", plaintext_msg);
        encrypt(plaintext_msg, &key)
    }
}

impl ContractInterface for Contract {
    // Constructor function that takes in VotingETH ethereum contract address
    #[no_mangle]
    fn construct() {
        // Create new random encryption key
        let key = generate_key();
        write_state!(ENCRYPTION_KEY => key);
    }

    #[no_mangle]
    fn encrypt_decrypt(plaintext_msg: Vec<u8>) {
        let enc_msg = Self::encrypt(&plaintext_msg);
        eprint!("The encrypted message: {:?}", enc_msg);
        let msg = Self::decrypt(&enc_msg);
        eprint!("The decrypted message bytes: {:?}", msg);
        if plaintext_msg != msg {
            panic!("Mismatching message after decryption");
        }
    }
}
