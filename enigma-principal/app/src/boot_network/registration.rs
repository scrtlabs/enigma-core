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


extern { fn ecall_get_random_seed(eid: sgx_enclave_id_t, retval: &mut sgx_status_t, rand_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> sgx_status_t; }

fn get_signed_random(eid: sgx_enclave_id_t) -> ([u8; 32], [u8; 65]) {
    let mut rand_out: [u8; 32] = [0; 32];
    let mut sig_out: [u8; 65] = [0; 65];
    let mut retval = sgx_status_t::default();
    unsafe { ecall_get_random_seed(eid, &mut retval, &mut rand_out, &mut sig_out); }
    assert_eq!(retval, sgx_status_t::SGX_SUCCESS); // TODO: Replace with good Error handling.
    (rand_out, sig_out)
}

// encoding in surface https://github.com/enigmampc/surface/blob/e179790347e03666ad24829545429bcb69867849/src/surface/communication/core/worker.py#L105

pub fn get_report()->Result<service::ASResponse, Error>{
    let service : service::AttestationService = service::AttestationService::new(constants::ATTESTATION_SERVICE_URL);
    let quote = String::from("AgAAANoKAAAHAAYAAAAAABYB+Vw5ueowf+qruQGtw+54eaWW7MiyrIAooQw/uU3eBAT/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAALcVy53ugrfvYImaDi1ZW5RueQiEekyu/HmLIKYvg6OxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACGcCDM4cgbYe6zQSwWQINFsDvd21kXGeteDakovCXPDwjJ31WG0K+wyDDRo8PFi293DtIr6DgNqS/guQSkglPJqAIAALbvs91Ugh9/yhBpAyGQPth+UWXRboGkTaZ3DY8U+Upkb2NWbLPkXbcMbB7c3SAfV4ip/kPswyq0OuTTiJijsUyOBOV3hVLIWM4f2wVXwxiVRXrfeFs/CGla6rGdRQpFzi4wWtrdKisVK5+Cyrt2y38Ialm0NqY9FIjxlodD9D7TC8fv0Xog29V1HROlY+PvRNa+f2qp858w8j+9TshkvOAdE1oVzu0F8KylbXfsSXhH7d+n0c8fqSBoLLEjedoDBp3KSO0bof/uzX2lGQJkZhJ/RSPPvND/1gVj9q1lTM5ccbfVfkmwdN0B5iDA5fMJaRz5o8SVILr3uWoBiwx7qsUceyGX77tCn2gZxfiOICNrpy3vv384TO2ovkwvhq1Lg071eXAlxQVtPvRYOGgBAABydn7bEWdP2htRd46nBkGIAoNAnhMvbGNbGCKtNVQAU0N9f7CROLPOTrlw9gVlKK+G5vM1X95KTdcOjs8gKtTkgEos021zBs9R+whyUcs9npo1SJ8GzowVwTwWfVz9adw2jL95zwJ/qz+y5x/IONw9iXspczf7W+bwyQpNaetO9xapF6aHg2/1w7st9yJOd0OfCZsowikJ4JRhAMcmwj4tiHovLyo2fpP3SiNGzDfzrpD+PdvBpyQgg4aPuxqGW8z+4SGn+vwadsLr+kIB4z7jcLQgkMSAplrnczr0GQZJuIPLxfk9mp8oi5dF3+jqvT1d4CWhRwocrs7Vm1tAKxiOBzkUElNaVEoFCPmUYE7uZhfMqOAUsylj3Db1zx1F1d5rPHgRhybpNpxThVWWnuT89I0XLO0WoQeuCSRT0Y9em1lsozSu2wrDKF933GL7YL0TEeKw3qFTPKsmUNlWMIow0jfWrfds/Lasz4pbGA7XXjhylwum8e/I");
    let as_response : service::ASResponse = service.get_report(&quote).unwrap();
    Ok(as_response)
}

pub fn rlp_encode_registration_params(certificate : &String , signature : &String, report : &String)->Vec<u8>{
    let clear = vec![report.as_str(), certificate.as_str(), signature.as_str()];
    let encoded = rlp::encode_list::<&str,&str>(&clear).to_vec();
    encoded
}

pub fn web3_test(){
    let (_eloop, transport) = web3::transports::Http::new("http://localhost:9545").unwrap();
    let web3 = web3::Web3::new(transport);
    // get accounts 
    let accounts = web3.eth().accounts().wait().unwrap();
    println!("Accounts: {:?}", accounts);
}

pub fn register_worker(signer : &String, report : &Vec<u8>){
    let (_eloop, transport) = web3::transports::Http::new("http://localhost:9545").unwrap();
    let web3 = web3::Web3::new(transport);
    let accounts = web3.eth().accounts().wait().unwrap();
    // load the contract 
    let eng_address : Address ="345cA3e014Aaf5dcA488057592ee47305D9B3e10".parse().unwrap();
    let contract = Contract::from_json(web3.eth(), eng_address, include_bytes!("./enigma.abi"),).unwrap();

    // register 
    let signer_addr : Address = signer.parse().unwrap();
    let mut options = Options::default();
    let mut gas : U256 = U256::from_dec_str("5999999").unwrap();
    options.gas = Some(gas);
    println!("send with gas = {:?}",gas );
    // call the register function
    contract.call("register",(signer_addr,report.to_vec(),12,),accounts[0],options ).wait().unwrap();
    // test3:validate that number commited 
    let res = contract.query("test_view",(),None,Options::default(),None);
    let num : U256 = res.wait().unwrap();
    println!("result from call = {:?}",num );
    // end of test3
    // confirm registration 
    // test2 : validate that the worker is registred 
    let result = contract.query("test_validate_registration",(signer_addr), None, Options::default(),None);
    let is_registred : bool = result.wait().unwrap();
    println!("is registred ? (yes ){}",is_registred );
    assert_eq!(is_registred, true);
    // end of test2
}

//setWorkersParams(uint256 seed, bytes sig)
pub fn set_random_number(eid: sgx_enclave_id_t){
    let (rand_seed, sig) = get_signed_random(eid);
    let the_seed : U256 = U256::from_big_endian(&rand_seed);
    println!("the seed in hex = {:?}",the_seed );
    // connect the Enigma contract 
     let (_eloop, transport) = web3::transports::Http::new("http://localhost:9545").unwrap();
    let web3 = web3::Web3::new(transport);
    let accounts = web3.eth().accounts().wait().unwrap();
    // load the contract 
    let eng_address : Address ="345cA3e014Aaf5dcA488057592ee47305D9B3e10".parse().unwrap();
    let contract = Contract::from_json(web3.eth(), eng_address, include_bytes!("./enigma.abi"),).unwrap();
    // set gas options for the tx 
    let mut options = Options::default();
    let mut gas : U256 = U256::from_dec_str("5999999").unwrap();
    options.gas = Some(gas);
    // set random seed 
    let ret = contract.call("setWorkersParams",(the_seed,sig.to_vec()),accounts[0],options ).wait().unwrap();
    println!("ret val = {:?}",ret );
    // test 
    // test get the new seed 
    let res = contract.query("test_seed",(),None,Options::default(),None);
    let test_seed : U256 = res.wait().unwrap();
    println!("to contract {:?} => returnd seed from contract : {:?}",the_seed,test_seed );
    // test get recoverd addr 
    let res = contract.query("test_recover_addr2",(),None,Options::default(),None);
    let test_addr : Address = res.wait().unwrap();
    println!("recoverd address from ec recover {:?}",test_addr );
}
pub fn run(eid: sgx_enclave_id_t){
    let as_response = get_report().unwrap();
    // certificate,signature,report_string are all need to be rlp encoded and send to register() func in enigma contract
    let certificate = as_response.result.certificate;
    let signature = as_response.result.signature;
    let report_string = as_response.result.report_string;
    // rlp encoding 
    let encoded : Vec<u8> = rlp_encode_registration_params(&certificate, &signature, &report_string);
    // register worker 
    // tested principal address from enigma-contract repo 
    // TODO:: this address is workers[msg.sender].signer == principal address. 
    // TODO:: the public key should be the key that is used for signing actually. 
    // TODO:: get the key from the enclave.
    let signer_addr = String::from("c44205c3aFf78e99049AfeAE4733a3481575CD26");
    register_worker(&signer_addr, &encoded);
    set_random_number(eid);
}