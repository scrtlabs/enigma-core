#![no_std]

extern crate eng_wasm;
extern crate eng_wasm_derive;
extern crate rustc_hex;
extern crate serde_derive;
extern crate serde;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;
use eng_wasm_derive::eth_contract;
use eng_wasm::String;
use std::collections::HashMap;
use rustc_hex::ToHex;

// VotingETH contract abi
#[eth_contract("VotingETH.json")]
struct EthContract;

// State key name "polls" holding a vector of Poll structs
static POLLS: &str = "polls";
// State key name "voting_eth_addr" holding eth address of VotingETH contract
static VOTING_ETH_ADDR: &str = "voting_eth_addr";

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
    // Read secret contract state to obtain vector of Poll structs (or new vector if uninitialized)
    fn get_polls() -> HashMap<u64, HashMap<String, U256>> {
        read_state!(POLLS).unwrap_or_default()
    }

    // Read voting address of VotingETH contract
    fn get_voting_eth_addr() -> String {
        read_state!(VOTING_ETH_ADDR).unwrap_or_default()
    }
}

impl ContractInterface for Contract {
    // Constructor function that takes in VotingETH ethereum contract address
    fn construct(voting_eth_addr: H160) {
        let voting_eth_addr_str: String = voting_eth_addr.to_hex();
        write_state!(VOTING_ETH_ADDR => voting_eth_addr_str);
    }

    // Cast vote function that takes poll ID, voter address, and vote - calls back to ETH
    fn cast_vote(poll_id: U256, voter: H256, vote: U256) {
        let mut polls = Self::get_polls();
        {
            let voter_info = polls.entry(poll_id.as_u64()).or_insert_with(HashMap::new);
            let key: String = voter.to_hex();
            assert!(!(*voter_info).contains_key(&key), "user has already voted in poll");
            (*voter_info).insert(key, vote);
        }
        write_state!(POLLS => polls);
        let voting_eth_addr: String = Self::get_voting_eth_addr();
        let c = EthContract::new(&voting_eth_addr);
        c.validateCastVote(poll_id);
    }

    // Tally poll function that takes poll ID - calls back to ETH
    fn tally_poll(poll_id: U256) {
        let polls = Self::get_polls();
        let mut tallied_quorum: U256 = U256::zero();
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
