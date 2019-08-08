#![no_std]
#![allow(unused_attributes)] // TODO: Remove on future nightly https://github.com/rust-lang/rust/issues/60050




extern crate eng_wasm;
extern crate eng_wasm_derive;
extern crate rustc_hex as hex;
#[macro_use]
extern crate serde_derive;
extern crate serde;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;
use serde::{Serialize, Deserialize};

// State key name "millionaires" holding a vector of Millionaire structs
static MILLIONAIRES: &str = "millionaires";

// Struct representing a Millionaire
#[derive(Serialize, Deserialize)]
pub struct Millionaire {
    address: H256, // field containing 32 byte hash type for millionaire's address
    net_worth: U256, // field containing 32 byte uint for millionaire's net worth
}

// Public-facing secret contract function declarations
#[pub_interface]
pub trait ContractInterface{
    fn add_millionaire(address: H256, net_worth: U256);
    fn compute_richest() -> H256;
}

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
