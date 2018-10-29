// general 
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use failure::Error;
use serde_derive::*;
use serde_json;
use tokio_core;
use std::time;
use std::thread;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
// web3 
use web3;
use web3::Web3;
use web3::futures::{Future, Stream};
use web3::contract::{Contract, Options};
use web3::types::{Address, U256, Bytes};
use web3::transports::Http;
// enigma modules 
use esgx::random_u;
use enigma_tools_u::web3_utils::enigma_contract;
use enigma_tools_u::web3_utils::enigma_contract::{EnigmaContract};
use enigma_tools_u::attestation_service::service;

// this struct holds parameters nessceary for emitting the random 
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct EmittParams{
    pub  eid: sgx_enclave_id_t, 
    pub  url : String, 
    pub  address: String ,
    pub  account : String, 
    pub  abi : String, 
    pub  gas_limit: String,
    pub  abi_path : String,
    pub max_epochs : Option<usize>,
}

// this trait should extend the EnigmaContract into Principal specific functions.
pub trait Principal {
     fn new(web3: Web3<Http>, eloop : web3::transports::EventLoopHandle ,address: &str, path: String, account: &str, url: String) -> Self;
     fn set_worker_params(&self,eid: sgx_enclave_id_t, gas_limit : &str)->Result<(),Error>;
     fn watch_blocks(&self, epoch_size : usize, polling_interval : u64, eid : sgx_enclave_id_t, gas_limit : String, max_epochs : Option<usize>);
}

impl Principal for EnigmaContract {
    fn new(web3: Web3<Http>, eloop : web3::transports::EventLoopHandle ,address: &str, path: String, account: &str, url: String) -> Self{
        Self::new(web3,eloop,address,path,account,url)
    }

    // set (seed,signature(seed)) into the enigma smart contract 
     fn set_worker_params(&self,eid: sgx_enclave_id_t, gas_limit : &str)->Result<(),Error>{
        
        // get seed,signature
        let (rand_seed, sig) = random_u::get_signed_random(eid);
        let the_seed : U256 = U256::from_big_endian(&rand_seed);
        println!("[---\u{25B6} seed: {} \u{25C0}---]",the_seed );
        // set gas options for the tx 
        let mut options = Options::default();
        let mut gas : U256 = U256::from_dec_str(gas_limit).unwrap();
        options.gas = Some(gas);
        
        // set random seed 
        self.contract.call("setWorkersParams",(the_seed,sig.to_vec()),self.account,options ).wait().unwrap();
        Ok(())
    }

    fn watch_blocks(&self, epoch_size : usize, polling_interval : u64, eid : sgx_enclave_id_t, gas_limit : String, max_epochs : Option<usize>){
        
        let prev_epoch = Arc::new(AtomicUsize::new(0));
        let MAX_EPOCHS = max_epochs.unwrap_or(0);
        let mut epoch_counter = 0;
        loop {
            //params 
            let url = self.url.clone();
            let address = self.address_str.clone();
            let account = self.account_str.clone();
            let abi =self.abi_str.clone();
            let abi_path = self.abi_path.clone();
            let gas_limit = gas_limit.clone();
            // loop
            let prev_epoch = Arc::clone(&prev_epoch);
            let future = self.web3.eth().block_number().then(move |res|{

                match res {
                    Ok(num) => {

                        let cur_block = num.low_u64() as usize;
                        let prev_block_ref = prev_epoch.load(Ordering::Relaxed);

                        if  prev_block_ref ==0 || cur_block >= prev_block_ref + epoch_size {

                            prev_epoch.swap(cur_block,  Ordering::Relaxed);
                            
                            println!("[\u{1F50A} ] @ block {}, prev block @ {} [\u{1F50A} ]", cur_block, prev_block_ref);
                            
                            let params = EmittParams{
                                eid : eid,
                                url : url.clone(),
                                address: address.clone(),
                                account : account.clone(), 
                                abi : abi.clone(),
                                gas_limit : gas_limit.clone(),
                                abi_path : abi_path.clone(),
                                max_epochs : None
                            };

                            match emitter_builder(params).set_worker_params(eid,&gas_limit){
                                Ok(_)=>{},
                                Err(e)=>{
                                    println!("[-] Error setting worker params in principale {:?}",e );
                                },
                            };
                        }
                    }   
                        Err(e) => println!("Error: {:?}", e),
                }

                Ok(())    
            });

            self.eloop.remote().spawn(|_| future);
            thread::sleep(time::Duration::from_secs(polling_interval));
            epoch_counter+=1;
            if MAX_EPOCHS != 0 && epoch_counter == MAX_EPOCHS{
                println!("[+] Principal: reached MAX_EPOCHS {} , stopping.",MAX_EPOCHS );
                break;
            }
        }
    }
}


// initialze a connection to the ethereum network 

pub fn connect(url : &str) -> (web3::transports::EventLoopHandle, Web3<Http>) {
        let (_eloop, http) = web3::transports::Http::new(url)
            .expect("unable to create Web3 HTTP provider");
        let w3 = web3::Web3::new(http);
        (_eloop, w3)
}

// emitt the random seed to the enigma smartt contract 
// TODO:: implement a bitter emitter 
pub fn emitter_builder(params : EmittParams)->enigma_contract::EnigmaContract{
    let (eloop, web3) = EnigmaContract::connect(params.url.as_str());
    // deployed contract address
    let address = params.address.as_str();
    // path to the build file of the contract 
    let path = params.abi_path.as_str();
    // the account owner that initializes 
    let account = params.account.as_str();
    let url = params.url.as_str();
    let enigma_contract : enigma_contract::EnigmaContract = Principal::new(web3,eloop, address, path.to_string(), account,url.to_string());
    enigma_contract
}