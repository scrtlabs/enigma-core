#![no_std]
#![feature(proc_macro_gen)]
#![feature(proc_macro_non_items)]


extern crate eng_wasm;
extern crate eng_wasm_derive;
extern crate rustc_hex;
#[macro_use]
extern crate serde_derive;
extern crate serde;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;
use eng_wasm_derive::eth_contract;
use eng_wasm::String;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::string::ToString;

#[eth_contract("VotingETH.json")]
struct EthContract;

// State key name "polls" holding a vector of Poll structs
static POLLS: &str = "polls";
// State key name "voting_eth_addr" holding eth address of VotingETH contract
static VOTING_ETH_ADDR: &str = "voting_eth_addr";

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

// Public-facing secret contract function declarations
#[pub_interface]
pub trait ContractInterface{
    fn construct(voting_eth_addr: H160);
    fn cast_vote(poll_id: U256, voter: H256, vote: U256);
    fn tally_poll(poll_id: U256);
}

pub struct Contract;

// Private functions accessible only by the secret contract
impl Contract {
    // Read secret contract state to obtain vector of Millionaires (or new vector if uninitialized)
    fn get_polls() -> HashMap<u64, HashMap<String, U256>> {
        read_state!(POLLS).unwrap_or_default()
    }

    fn get_voting_eth_addr() -> String {
        read_state!(VOTING_ETH_ADDR).unwrap_or_default()
    }
}

impl ContractInterface for Contract {
    #[no_mangle]
    fn construct(voting_eth_addr: H160) {
        let voting_eth_addr_str: String = eformat!("{:?}", voting_eth_addr);
        write_state!(VOTING_ETH_ADDR => voting_eth_addr_str);
    }

    #[no_mangle]
    fn cast_vote(poll_id: U256, voter: H256, vote: U256) {
        let mut polls = Self::get_polls();
        eprint!("POLLS = {:?}", polls);
        {
            let voter_info = polls.entry(poll_id.as_u64()).or_insert(HashMap::new());
            let key = eformat!("{:?}", voter);
            assert!(!(*voter_info).contains_key(&key), "user has already voted in poll");
            (*voter_info).insert(key, vote);
        }
        write_state!(POLLS => polls);
        let voting_eth_addr: String = Self::get_voting_eth_addr();
        eprint!("voting_eth_addr = {:?}", &voting_eth_addr);
        let c = EthContract::new(&voting_eth_addr);
        c.validateCastVote(poll_id);
    }

    // Create a new poll
    #[no_mangle]
    fn tally_poll(poll_id: U256) {
        let polls = Self::get_polls();
        let mut tallied_quorum: U256 = 0.into();
        if let Some(voter_info) = polls.get(&poll_id.as_u64()) {
            for val in voter_info.values() {
                tallied_quorum = tallied_quorum.checked_add(*val).unwrap();
            }
            tallied_quorum = tallied_quorum.checked_mul(100.into()).unwrap().checked_div(voter_info.len().into()).unwrap()
        }
        let voting_eth_addr: String = Self::get_voting_eth_addr();
        let c = EthContract::new(&voting_eth_addr);
        c.validateTallyPoll(poll_id, tallied_quorum);
    }
}
