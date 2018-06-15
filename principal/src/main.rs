//extern crate rustc_hex;
//extern crate web3;
//extern crate config;
//
//use std::str;
//use std::collections::HashMap;
//use std::fs::File;
//use std::io::Read;
//use web3::futures::Future;
//use web3::contract::{Contract, Options};
//use web3::types::{Address, H160, U256};
//use rustc_hex::FromHex;

fn main() {

//    let app_config = read_config();
//    // Print out our settings (as a HashMap)
//    let key = String::from("enigma_path");
//    let filename = app_config.get(&key).unwrap();
//    println!("{:?}", filename);
//
//    let address_key = String::from("enigma_address");
//    let accounts = web3.eth().accounts().wait().unwrap();
//    let account = accounts[0];
//    println!("the accounts: {:?}", account);
//
//    let mut f = File::open(filename).expect("file not found");
//
//    let mut buffer = vec![0; 10];
//    f.read_to_end(&mut buffer).unwrap();
////        .expect("something went wrong reading the file");
//
////    let mut buffer = String::new();
////    f.read_to_string(&mut buffer).unwrap();
////    println!("the buffer: {:?}", buffer);
////
////    // Accessing existing contract
//    println!("the contract address: {:?}", contract_address);
//    let contract = Contract::from_json(
//        web3.eth(),
//        contract_address,
//        &buffer,
//    ).unwrap();
////
////    let result = contract.query("balanceOf", (my_account, ), None, Options::default(), None);
////    let balance_of: U256 = result.wait().unwrap();
////    assert_eq!(balance_of, 1_000_000.into());
}