#![no_std]

extern crate eng_wasm;
extern crate eng_wasm_derive;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;

#[pub_interface]
pub trait ContractInterface{
    /// Flipping the coin. Uses true sgx randomness.
    fn flip() -> bool;

    /// Player 1 commits to a coin value
    fn commit(commitment: bool);

    /// Player 2 guesses the value that player 1 was committed to. The commitment is removed.
    /// True is returned on successful guess.
    fn guess(guess: bool) -> bool;
}

const COMMITMENT_KEY: &'static str = "commitment";

pub struct Contract;

impl ContractInterface for Contract {
    fn flip() -> bool {
        let result: u8 = Rand::gen();
        result % 2 == 1
    }

    fn commit(commitment: bool) {
        let val: Option<Value> = read_state!(COMMITMENT_KEY);
        if val.is_none() {
            write_state!(COMMITMENT_KEY => commitment);
        }
    }

    fn guess(guess: bool) -> bool {
        let val: Option<Value> = remove_from_state!(COMMITMENT_KEY);
        match val {
            Some(commitment) => commitment == guess,
            _ => false
        }
    }
}

