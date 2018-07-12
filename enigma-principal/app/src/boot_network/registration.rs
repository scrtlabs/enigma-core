//sgx 
use sgx_types::{uint8_t, uint32_t};
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
// general 
use rlp;
use enigma_tools_u;
use enigma_tools_u::attestation_service::service;
use enigma_tools_u::attestation_service::constants;
use failure::Error;
//web3
use web3;
use web3::futures::{Future, Stream};
use web3::contract::{Contract, Options};
use web3::types::{Address, U256, Bytes};
use rustc_hex::FromHex;
// tokio+polling blocks 
use tokio_core;
use web3::types::FilterBuilder;
use std::time;
use std::thread;
use web3::Web3;
use web3::transports::Http;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
// formal 
use boot_network::enigma_contract;
use boot_network::principal_utils::Principal;

pub fn get_rlp_encoded_report()->Result<(Vec<u8>,service::ASResponse),Error>{
    let service : service::AttestationService = service::AttestationService::new(constants::ATTESTATION_SERVICE_URL);
    let quote = String::from("AgAAANoKAAAHAAYAAAAAABYB+Vw5ueowf+qruQGtw+54eaWW7MiyrIAooQw/uU3eBAT/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAALcVy53ugrfvYImaDi1ZW5RueQiEekyu/HmLIKYvg6OxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACGcCDM4cgbYe6zQSwWQINFsDvd21kXGeteDakovCXPDwjJ31WG0K+wyDDRo8PFi293DtIr6DgNqS/guQSkglPJqAIAALbvs91Ugh9/yhBpAyGQPth+UWXRboGkTaZ3DY8U+Upkb2NWbLPkXbcMbB7c3SAfV4ip/kPswyq0OuTTiJijsUyOBOV3hVLIWM4f2wVXwxiVRXrfeFs/CGla6rGdRQpFzi4wWtrdKisVK5+Cyrt2y38Ialm0NqY9FIjxlodD9D7TC8fv0Xog29V1HROlY+PvRNa+f2qp858w8j+9TshkvOAdE1oVzu0F8KylbXfsSXhH7d+n0c8fqSBoLLEjedoDBp3KSO0bof/uzX2lGQJkZhJ/RSPPvND/1gVj9q1lTM5ccbfVfkmwdN0B5iDA5fMJaRz5o8SVILr3uWoBiwx7qsUceyGX77tCn2gZxfiOICNrpy3vv384TO2ovkwvhq1Lg071eXAlxQVtPvRYOGgBAABydn7bEWdP2htRd46nBkGIAoNAnhMvbGNbGCKtNVQAU0N9f7CROLPOTrlw9gVlKK+G5vM1X95KTdcOjs8gKtTkgEos021zBs9R+whyUcs9npo1SJ8GzowVwTwWfVz9adw2jL95zwJ/qz+y5x/IONw9iXspczf7W+bwyQpNaetO9xapF6aHg2/1w7st9yJOd0OfCZsowikJ4JRhAMcmwj4tiHovLyo2fpP3SiNGzDfzrpD+PdvBpyQgg4aPuxqGW8z+4SGn+vwadsLr+kIB4z7jcLQgkMSAplrnczr0GQZJuIPLxfk9mp8oi5dF3+jqvT1d4CWhRwocrs7Vm1tAKxiOBzkUElNaVEoFCPmUYE7uZhfMqOAUsylj3Db1zx1F1d5rPHgRhybpNpxThVWWnuT89I0XLO0WoQeuCSRT0Y9em1lsozSu2wrDKF933GL7YL0TEeKw3qFTPKsmUNlWMIow0jfWrfds/Lasz4pbGA7XXjhylwum8e/I");
    let (rlp_encoded, as_response ) = service.rlp_encode_registration_params(&quote).unwrap();
    Ok((rlp_encoded,as_response))
}


fn setup() -> (web3::transports::EventLoopHandle, Web3<Http>) {
        let (_eloop, http) = web3::transports::Http::new("http://localhost:9545")
            .expect("unable to create Web3 HTTP provider");
        let w3 = web3::Web3::new(http);
        (_eloop, w3)
}


pub fn enigma_contract_builder()->enigma_contract::EnigmaContract{
    let (eloop, web3) = setup();
    // deployed contract address
    let address = "345cA3e014Aaf5dcA488057592ee47305D9B3e10";
    // path to the build file of the contract 
    let path = "/root/enigma-core/enigma-principal/app/src/boot_network/enigma_full.abi";
    // the account owner that initializes 
    let account = "627306090abab3a6e1400e9345bc60c78a8bef57";
    let url = "http://localhost:9545";
    let enigma_contract : enigma_contract::EnigmaContract = Principal::new(web3,eloop, address, path, account,url);
    enigma_contract
}
// enigma contract 
pub fn run(eid: sgx_enclave_id_t){
    let enigma_contract = enigma_contract_builder();
    // fetch report 
    let (encoded_report , as_response ) = get_rlp_encoded_report().unwrap();
    // register worker 
    // signer_addr = address representation of the public key generated in the report 
    let signer = String::from("c44205c3aFf78e99049AfeAE4733a3481575CD26");
    let gas_limit = String::from("5999999");
    enigma_contract.register_as_worker(&signer,&encoded_report,&gas_limit ).unwrap();
    // begin loop process
    //fn watch_blocks(&self, epoch_size : usize, delay_seconds : u64){
    let epoch_size = 2;
    let polling_interval = 1;
    enigma_contract.watch_blocks(epoch_size, polling_interval, eid, gas_limit);
}
