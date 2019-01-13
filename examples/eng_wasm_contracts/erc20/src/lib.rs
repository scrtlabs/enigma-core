#![no_std]
#![feature(proc_macro_gen)]
#![feature(proc_macro_non_items)]


extern crate eng_wasm;
extern crate eng_wasm_derive;
extern crate rustc_hex as hex;
#[macro_use]
extern crate more_asserts;
#[macro_use]
extern crate serde_derive;
extern crate serde;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;
use eng_wasm::String;
use eng_wasm::from_utf8;
use hex::ToHex;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

static TOTAL_SUPPLY: &str = "total_supply";

#[pub_interface]
pub trait Erc20Interface{

    fn mint(addr: H256, tokens: U256);
    fn total_supply() -> U256;
    fn balance_of(token_owner: H256) -> U256;
    fn allowance(owner: H256, spender: H256) -> U256;
    fn transfer(from: H256, to: H256, tokens: U256);
    fn approve(token_owner: H256, spender: H256, tokens: U256);
    fn transfer_from(owner: H256, spender: H256, to: H256, tokens: U256);
}

#[derive(Serialize, Deserialize)]
pub struct User {
    balance : u64,
    approved : HashMap<String, u64>,
}

pub struct Contract;
impl Erc20Interface for Contract {

    #[no_mangle]
    fn mint(addr: H256, tokens: U256) {
        let total_supply: u64 = match read_state!(TOTAL_SUPPLY) {
            Some(amount) => amount,
            None => 0,
        };
        let mut user_addr = match read_state!(&addr.to_hex()) {
            Some(user) => user,
            None => User{balance: 0, approved: HashMap::new()},
        };

        user_addr.balance = user_addr.balance + tokens.as_u64();
        write_state!(&addr.to_hex() => user_addr, TOTAL_SUPPLY => (total_supply + tokens.as_u64()));
        let read_val : User = read_state!(&addr.to_hex()).unwrap();
    }

    // todo: check if possible to have total_supply in state in this form, otherwise, put in balances
    #[no_mangle]
    fn total_supply() -> U256 {
        match read_state!(TOTAL_SUPPLY) {
            Some(amount) => amount,
            None => 0,
        }.into()
    }

    #[no_mangle]
    fn balance_of(token_owner: H256) -> U256 {

        let user: User = match read_state!(&token_owner.to_hex()) {
            Some(user) => user,
            None => User {balance : 0, approved : HashMap::new()},
        };
        user.balance.into()
    }

    #[no_mangle]
    fn allowance(owner: H256, spender: H256) -> U256 {
        let user: User = match read_state!(&owner.to_hex()) {
            Some(user) => user,
            None => User {balance : 0, approved : HashMap::new()},
        };
        match user.approved.get(&spender.to_hex()) {
            Some(amount) => *amount,
            None => 0,
        }.into()
    }

    #[no_mangle]
    fn transfer(from: H256, to: H256, tokens: U256) {
        let mut from_user : User = read_state!(&from.to_hex()).expect("User does not own tokens - invalid action");
        assert_lt!(from_user.balance, tokens.as_u64());
        let mut to_user : User = match read_state!(&to.to_hex()) {
            Some(user) => user,
            None => User {balance: 0, approved: HashMap::new()}
        };
        from_user.balance = from_user.balance - tokens.as_u64();
        to_user.balance = to_user.balance + tokens.as_u64();
        write_state!(&from.to_hex() => from_user, &to.to_hex() => to_user);
//         for test: check if the amount was updated
        let final_to_amount: User = read_state!(&to.to_hex()).unwrap();
    }

    #[no_mangle]
    fn approve(token_owner: H256, spender: H256, tokens: U256){
        let mut owner_user : User = read_state!(&token_owner.to_hex()).expect("User does not own tokens - invalid action");
        assert_lt!(owner_user.balance, tokens.as_u64());

        owner_user.approved.insert(spender.to_hex(), tokens.as_u64());
        write_state!(&token_owner.to_hex() => owner_user);
    }

    #[no_mangle]
    fn transfer_from(owner: H256, spender: H256, to: H256, tokens: U256) {

        let mut owner_user : User = read_state!(&owner.to_hex()).expect("User does not own this amount of tokens - invalid action");
        assert_lt!(owner_user.balance, tokens.as_u64());

        let allowed_balance: u64 = match owner_user.approved.get(&spender.to_hex()) {
            Some(amount) => *amount,
            None => 0,
        };
        assert_lt!(allowed_balance, tokens.as_u64());

        let mut to_user: User = match read_state!(&to.to_hex()) {
            Some(user) => user,
            None => User{balance : 0, approved: HashMap::new()},
        };
        to_user.balance = to_user.balance + tokens.as_u64();
        owner_user.balance = owner_user.balance - tokens.as_u64();
        owner_user.approved.insert(spender.to_hex(),(allowed_balance - tokens.as_u64()));
        write_state!(&owner.to_hex() => owner_user, &to.to_hex() => to_user);
//         for test: check if the amount was updated
        let final_to_amount: User = read_state!(&to.to_hex()).unwrap();
    }
}

#[no_mangle]
pub fn deploy() {}
