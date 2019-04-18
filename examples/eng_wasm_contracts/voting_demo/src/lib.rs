#![no_std]
#![feature(proc_macro_gen)]
#![feature(proc_macro_non_items)]


extern crate eng_wasm;
extern crate eng_wasm_derive;
extern crate rustc_hex as hex;
#[macro_use]
extern crate serde_derive;
extern crate serde;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;
use eng_wasm::String;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::string::ToString;

// State key name "polls" holding a vector of Poll structs
static POLLS: &str = "polls";
// State key name "poll_count" holding number of polls
static POLL_COUNT: &str = "poll_count";

// Struct representing a Voter
#[derive(Serialize, Deserialize, Debug)]
pub enum PollStatus {
    InProgress,
    Passed,
    Rejected,
}

impl Default for PollStatus {
    fn default() -> Self { PollStatus::InProgress }
}

// Struct representing a Poll
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Poll {
    creator: H256, // field containing bool for whether Voter has voted yet
    status: PollStatus, // field containing bool for whether Voter has voted yet
    quorum_percentage: U256, // field containing bool for whether Voter has voted yet
    yay_votes: U256, // field containing bool for whether Voter has voted yet
    nay_votes: U256, // field containing bool for whether Voter has voted yet
    description: String, // field containing bool for whether Voter has voted yet
    voter_info : HashMap<String, U256>, // field containing bool for whether Voter has voted yet
}

// Public-facing secret contract function declarations
#[pub_interface]
pub trait ContractInterface{
    fn create_poll(creator: H256, quorum_percentage: U256, description: String);
    fn cast_vote(poll_id: U256, voter: H256, vote: U256);
    fn compute_result(poll_id: U256) -> bool;
}

pub struct Contract;

// Private functions accessible only by the secret contract
impl Contract {
    // Read secret contract state to obtain vector of Millionaires (or new vector if uninitialized)
    fn get_polls() -> Vec<Poll> {
        read_state!(POLLS).unwrap_or_default()
    }

    // Read secret contract state to obtain vector of Millionaires (or new vector if uninitialized)
    fn get_poll_count() -> U256 {
        read_state!(POLL_COUNT).unwrap_or_default()
    }
}

impl ContractInterface for Contract {
    // Create a new poll
    #[no_mangle]
    fn create_poll(creator: H256, quorum_percentage: U256, description: String) {
        assert!(quorum_percentage <= U256::from(100), "quorum percentage must be less than or equal to 100%");
        let mut polls = Self::get_polls();
        polls.push(Poll {
            creator,
            quorum_percentage,
            description: description.clone(),
            ..Default::default()
        });
        let poll_count = Self::get_poll_count() + 1;
        write_state!(POLLS => polls, POLL_COUNT => poll_count);
    }

    // Cast a new vote
    #[no_mangle]
    fn cast_vote(poll_id: U256, voter: H256, vote: U256) {
        let mut polls = Self::get_polls();
        if let Some(poll) = polls.get_mut(poll_id.as_usize()) {
            let key = eformat!("{:?}", voter);
            assert!(!(*poll).voter_info.contains_key(&key), "user has already voted in poll");
            (*poll).voter_info.insert(key, vote);
        }
        write_state!(POLLS => polls);
    }

    // Create a new poll
    #[no_mangle]
    fn compute_result(poll_id: U256) -> bool {
        let polls = Self::get_polls();
        let mut sum: U256 = 0.into();
        if let Some(poll) = polls.get(poll_id.as_usize()) {
            for val in poll.voter_info.values() {
                sum = sum.checked_add(*val).unwrap();
            }
            sum.checked_mul(100.into()).unwrap() >= poll.quorum_percentage.checked_mul(poll.voter_info.len().into()).unwrap()
        } else {
            false
        }
    }
}
