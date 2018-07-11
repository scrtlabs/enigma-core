// sgx 
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use esgx::random_u;
// general 
use boot_network::enigma_contract::{EnigmaContract};
use enigma_tools_u::attestation_service::service;
use failure::Error;
// web3 
use web3;
use web3::Web3;
use web3::futures::{Future, Stream};
use web3::contract::{Contract, Options};
use web3::types::{Address, U256, Bytes};
use web3::transports::Http;
// tokio+polling blocks 
use tokio_core;
use std::time;
use std::thread;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// this trait should extend the EnigmaContract into Principal specific functions.
pub trait Principal {
     fn new(web3: Web3<Http>, eloop : web3::transports::EventLoopHandle ,address: &str, path: &str, account: &str) -> Self;
     fn set_worker_params(&self,eid: sgx_enclave_id_t, gas_limit : String)->Result<(),Error>;
     fn watch_blocks(&self, epoch_size : usize, polling_interval : u64, eid : sgx_enclave_id_t);
     fn shit(&self);
}

impl Principal for EnigmaContract {
    fn new(web3: Web3<Http>, eloop : web3::transports::EventLoopHandle ,address: &str, path: &str, account: &str) -> Self{
        Self::new(web3,eloop,address,path,account)
    }
    fn shit(&self){
        let eid : sgx_enclave_id_t = 0; 
        // get seed,signature
        let (rand_seed, sig) = random_u::get_signed_random(eid);
        let the_seed : U256 = U256::from_big_endian(&rand_seed);
        
        // set gas options for the tx 
        let mut options = Options::default();
        let mut gas : U256 = U256::from_dec_str(&String::from("999")).unwrap();
        options.gas = Some(gas);
        
        // set random seed 
        self.contract.call("setWorkersParams",(the_seed,sig.to_vec()),self.account,options ).wait().unwrap();
     }
    // set (seed,signature(seed)) into the enigma smart contract 
    fn set_worker_params(&self,eid: sgx_enclave_id_t, gas_limit : String)->Result<(),Error>{
        
        // get seed,signature
        let (rand_seed, sig) = random_u::get_signed_random(eid);
        let the_seed : U256 = U256::from_big_endian(&rand_seed);
        
        // set gas options for the tx 
        let mut options = Options::default();
        let mut gas : U256 = U256::from_dec_str(&gas_limit).unwrap();
        options.gas = Some(gas);
        
        // set random seed 
        self.contract.call("setWorkersParams",(the_seed,sig.to_vec()),self.account,options ).wait().unwrap();
        Ok(())
    }
    fn watch_blocks(&self, epoch_size : usize, polling_interval : u64, eid : sgx_enclave_id_t){
        
        let prev_epoch = Arc::new(AtomicUsize::new(0));
        //let cloned_ac = self.account.clone();
        //let contract_addr = self.contract.address();
        loop {
            let prev_epoch = Arc::clone(&prev_epoch);
            let future = self.web3.eth().block_number().then(move |res|{

                match res {
                    Ok(num) => {

                        let cur_block = num.low_u64() as usize;
                        let prev_block_ref = prev_epoch.load(Ordering::Relaxed);

                        if  prev_block_ref ==0 || cur_block >= prev_block_ref + epoch_size{
                            prev_epoch.swap(cur_block,  Ordering::Relaxed);
                            println!("emit random, current block {} , prev block {} , next prev {} ", cur_block, prev_block_ref , prev_epoch.load(Ordering::Relaxed));
                            // https://paste.ubuntu.com/p/B8wJN47kjV/
                            // let path = "/root/enigma-core/enigma-principal/app/src/boot_network/enigma_full.abi";
                            // let gas_limit = String::from("5999999");
                            //  emit_worker_params(eid, gas_limit, cloned_ac,contract_addr.clone(),&path);
                        }
                    }   
                        Err(e) => println!("Error: {:?}", e),
                }

                Ok(())    
            });

            self.eloop.remote().spawn(|_| future);
            thread::sleep(time::Duration::from_secs(polling_interval));
        }
    }
}


// initialze a connection to the ethereum network 

fn setup() -> (web3::transports::EventLoopHandle, Web3<Http>) {
        let (_eloop, http) = web3::transports::Http::new("http://localhost:9545")
            .expect("unable to create Web3 HTTP provider");
        let w3 = web3::Web3::new(http);
        (_eloop, w3)
}

pub fn emit_worker_params(eid: sgx_enclave_id_t, gas_limit : String,account : Address, contract_address: Address, path: &str)->Result<(),Error>{
    let contract = contract_instance(contract_address, path);
    // get seed,signature
    let (rand_seed, sig) = random_u::get_signed_random(eid);
    let the_seed : U256 = U256::from_big_endian(&rand_seed);
    
    // set gas options for the tx 
    let mut options = Options::default();
    let mut gas : U256 = U256::from_dec_str(&gas_limit).unwrap();
    options.gas = Some(gas);

    // set random seed 
    contract.call("setWorkersParams",(the_seed,sig.to_vec()),account,options ).wait().unwrap();
    Ok(())
}


pub fn contract_instance(address: Address, path: &str) -> Contract<Http> {
       
       let (eloop,web3) = setup();
       
       let abi = EnigmaContract::load_abi(path);
       
       let contract = Contract::from_json(
           web3.eth(), 
           address, 
           abi.unwrap().as_bytes(),
         ).expect("unable to fetch the deployed contract on the Ethereum provider");

        contract
    }