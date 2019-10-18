// Rust’s standard library provides a lot of useful functionality
// but WebAssembly does not support all of it;
// eng_wasm exposes a subset of std.
#![no_std]

// The eng_wasm crate allows to use the Enigma runtime, which provides:
// reading and writing to state, printing, random and more
extern crate eng_wasm;

// The eng_wasm_derive crate provides the following:
// * Functions exposed by the contract that may be called from the Enigma network
// * Ability to call functions of Ethereum contracts from ESC
extern crate eng_wasm_derive;

extern crate serde;

use eng_wasm::*;

// The [pub_interface] trait is required for the definition of ESC public functions 
use eng_wasm_derive::pub_interface;

// Enables the serializing and deserializing of custom struct types
use serde::{Serialize, Deserialize};

// Const representing the millionaire structs vector to be saved at the contract state
static MILLIONAIRES: &str = "millionaires";

// Millionaire struct
#[derive(Serialize, Deserialize)]
pub struct Millionaire {
    address: H256, // field containing 32 byte hash type for millionaire's address
    net_worth: U256, // field containing 32 byte uint for millionaire's net worth
}

// Public secret contract function declarations
#[pub_interface]
pub trait ContractInterface{
    fn add_millionaire(address: H256, net_worth: U256);
    fn compute_richest() -> H256;
}

// Public Contract struct which will consist of private and public-facing secret contract functions
pub struct Contract;

// Private functions accessible only by the secret contract
impl Contract {
    // Read secret contract state to obtain vector of Millionaires (or new vector if uninitialized)
    fn get_millionaires() -> Vec<Millionaire> {
        match read_state!(MILLIONAIRES) {
            Some(vec) => vec,
            None => Vec::new(),
        }
    }
}

impl ContractInterface for Contract {
    // Add millionaire with 32-byte hash type for address and 32-byte uint for net worth
    fn add_millionaire(address: H256, net_worth: U256) {
        // Read state to get vector of Millionaires
        let mut millionaires = Self::get_millionaires();
        // Append a new Millionaire struct to this vector
        millionaires.push(Millionaire {
            address,
            net_worth,
        });
        // Write the updated vector to contract's state
        write_state!(MILLIONAIRES => millionaires);
    }

    // Compute the richest millionaire by returning the 32-byte hash type for the address
    fn compute_richest() -> H256 {
        // Read state to get vector of Millionaires and obtain the struct corresponding to the
        // richest millionaire by net worth
        match Self::get_millionaires().iter().max_by_key(|m| m.net_worth) {
            // Return millionaire's address
            Some(millionaire) => {
                millionaire.address
            },
            // Return empty address
            None => U256::from(0).into(),
        }
    }
}
