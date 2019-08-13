#![no_std]

extern crate eng_wasm;
extern crate eng_wasm_derive;
extern crate enigma_crypto;
#[macro_use]
extern crate serde;
extern crate rustc_hex;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;
use eng_wasm::String;
use std::collections::HashMap;
use enigma_crypto::{KeyPair, hash::Keccak256};
use rustc_hex::ToHex;

static TOTAL_SUPPLY: &str = "total_supply";
static CONTRACT_OWNER: &str = "owner";

#[pub_interface]
pub trait Erc20Interface{
    fn construct(contract_owner: H256, total_supply: U256);
    /// creates new tokens and sends to the specified address
    fn mint(owner: H256, addr: H256, tokens: U256, sig: Vec<u8>);
    /// get the total_supply
    fn total_supply() -> U256;
    /// get the balance of the specified address
    fn balance_of(token_owner: H256) -> U256;
    /// get the allowed amount of the owner tokens to be spent by the spender address
    fn allowance(owner: H256, spender: H256) -> U256;
    /// transfer tokens from 'from' address to the 'to' address.
    /// the function panics if the 'from' address does not have enough tokens.
    fn transfer(from: H256, to: H256, tokens: U256, sig: Vec<u8>);
    /// approve the 'spender' address to spend 'tokens' from the 'owner's address balance.
    /// the function panics if the 'owner' address does not have enough tokens.
    fn approve(token_owner: H256, spender: H256, tokens: U256, sig: Vec<u8>);
    /// 'spender' address transfers tokens on behalf of the owner address to the 'to' address.
    /// the function panics if the 'owner' address does not have enough tokens or the 'spender'
    /// address does not have enough tokens as well.
    fn transfer_from(owner: H256, spender: H256, to: H256, tokens: U256, sig: Vec<u8>);
}

/// User object holds all information of a user address
#[derive(Serialize, Deserialize, Default)]
pub struct User {
    /// number of tokens a user owns
    balance : U256,
    /// a HashMap which contains all authorised spenders by the user
    approved : HashMap<String, U256>,
}

impl User {
    pub fn get_approved(&self, addr: H256) -> U256 {
        let addr: String = addr.to_hex();
        *self.approved.get(&addr).unwrap_or(&Default::default())
    }

    pub fn insert_approved(&mut self, addr: H256, amount: U256) {
        let addr: String = addr.to_hex();
        self.approved.insert(addr, amount);
    }
}

pub struct Contract;

impl Contract {
    /// receives an address and returns it's User object,
    /// if it does not exist, it creates a new object.
    fn get_user(user: H256) -> User {
        read_state!(&user.to_hex::<String>()).unwrap_or_default()
    }

    // todo: change this function in enigma-crypto so it will
    // todo: be able to run without std and then remove it from here.
    fn prepare_hash_multiple<B: AsRef<[u8]>>(messages: &[B]) -> Vec<u8> {
        // wasmi is using a 32 bit target as oppose to the actual machine that
        // is a 64 bit target. therefore using u64 and not usize
        let mut res = Vec::with_capacity(messages.len() * mem::size_of::<u64>());
        for msg in messages {
            let msg = msg.as_ref();
            let len = (msg.len() as u64).to_be_bytes();
            res.extend_from_slice(&len);
            res.extend_from_slice(&msg);
        }
        res
    }

    /// verify if the address that is sending the tokens is the one who actually sent the transfer.
    fn verify(signer: H256, addr: H256, amount: U256, sig: Vec<u8>) -> bool {
        let msg = [&addr.to_vec()[..], &amount.as_u64().to_be_bytes()];
        let to_verify = Self::prepare_hash_multiple(&msg);
        let mut new_sig: [u8; 65] = [0u8; 65];
        new_sig.copy_from_slice(&sig[..65]);

        let accepted_pubkey = KeyPair::recover(&to_verify, new_sig).unwrap();
        *signer == *accepted_pubkey.keccak256()
    }
}

impl Erc20Interface for Contract {

    fn construct(owner_of_the_contract: H256, total_supply: U256) {
        let mut user_addr = Self::get_user(owner_of_the_contract);
        user_addr.balance = total_supply;
        let user_addr_str: String = owner_of_the_contract.to_hex();
        write_state!(TOTAL_SUPPLY => total_supply,
                     CONTRACT_OWNER => owner_of_the_contract,
                     &user_addr_str => user_addr
        );
    }

    fn mint(owner: H256, addr: H256, tokens: U256, sig: Vec<u8>) {
        // verify the owner is the one who is minting.
        let contract_owner: H256 = read_state!(CONTRACT_OWNER).unwrap();
        assert_eq!(owner, contract_owner);
        assert!(Self::verify(owner, addr, tokens, sig));

        let total_supply: U256 = read_state!(TOTAL_SUPPLY).unwrap_or_default();
        let mut user_addr = Self::get_user(addr);

        // update the user object and write to the state
        user_addr.balance = user_addr.balance + tokens;
        write_state!(&addr.to_hex::<String>() => user_addr, TOTAL_SUPPLY => total_supply + tokens);
    }

    fn total_supply() -> U256 {
        read_state!(TOTAL_SUPPLY).unwrap_or_default()
    }

    fn balance_of(token_owner: H256) -> U256 {
        let user: User = Self::get_user(token_owner);
        user.balance
    }

    fn allowance(owner: H256, spender: H256) -> U256 {
        let user: User = Self::get_user(owner);
        user.get_approved(spender)
    }

    fn transfer(from: H256, to: H256, tokens: U256, sig: Vec<u8>) {
        assert!(Self::verify(from.clone(), to.clone(), tokens, sig));
        let mut from_user : User = Self::get_user(from);

        // panic if the 'from' address does not have enough tokens.
        assert!(from_user.balance >= tokens, "invalid action: user does not have enough tokens");
        let mut to_user : User = Self::get_user(to);

        // update the balances and write the user objects to the state
        from_user.balance = from_user.balance - tokens;
        to_user.balance = to_user.balance + tokens;
        write_state!(&from.to_hex::<String>() => from_user, &to.to_hex::<String>() => to_user);
    }

    fn approve(token_owner: H256, spender: H256, tokens: U256, sig: Vec<u8>) {
        assert!(Self::verify(token_owner.clone(), spender.clone(), tokens, sig));
        let mut owner_user : User = Self::get_user(token_owner);
        assert!(owner_user.balance >= tokens, "invalid action: owner does not have enough tokens");
        // update the object and write it to the state
        owner_user.insert_approved(spender, tokens);
        write_state!(&token_owner.to_hex::<String>() => owner_user);
    }

    fn transfer_from(owner: H256, spender: H256, to: H256, tokens: U256, sig: Vec<u8>) {
        assert!(Self::verify(spender.clone(), to.clone(), tokens, sig));
        let mut owner_user : User = Self::get_user(owner);
        // panic if the owner does not own the amount of tokens
        assert!(owner_user.balance >= tokens, "invalid action: owner does not have enough tokens");

        let allowed_balance = owner_user.get_approved(spender);
        // panic if the spender is not approved to spend as much as tokens
        assert!(allowed_balance >= tokens, "invalid action: user is not allowed to spend this amount of tokens");

        let mut to_user: User = Self::get_user(to);

        // update the objects and write to the state
        to_user.balance = to_user.balance + tokens;
        owner_user.balance = owner_user.balance - tokens;
        owner_user.insert_approved(spender, allowed_balance - tokens);
        write_state!(&owner.to_hex::<String>() => owner_user, &to.to_hex::<String>() => to_user);
    }
}
