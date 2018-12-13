// general 
use sgx_types::sgx_enclave_id_t;
use failure::Error;
use serde_derive::*;
use std::time;
use std::thread;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use rustc_hex::{FromHex, ToHex};
// web3
use web3::futures::{Future, Stream};
use web3::contract::{Contract, Options};
use web3::types::{Address, U256};
use web3::transports::Http;
// enigma modules 
use esgx::random_u;
use enigma_tools_u::web3_utils::enigma_contract::{EnigmaContract};

// this struct holds parameters necessary for emitting the random
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct EmitParams {
    pub eid: sgx_enclave_id_t,
    pub address: String ,
    pub account : String,
    pub gas_limit: u64,
    pub max_epochs : Option<usize>,
}

// this trait should extend the EnigmaContract into Principal specific functions.
pub trait Principal {
     fn new(address: &str, path: String, account: &str, url: &str) -> Result<Self, Error> where  Self: Sized;

     fn set_worker_params(&self,eid: sgx_enclave_id_t, gas_limit : u64)->Result<(),Error>;

     fn set_worker_params_internal(contract: &Contract<Http>, account: &Address, eid: sgx_enclave_id_t, gas_limit : u64) -> Result<(),Error>;

     fn watch_blocks(&self, epoch_size: usize, polling_interval : u64, eid: sgx_enclave_id_t, gas_limit: u64, max_epochs: Option<usize>);
}


impl Principal for EnigmaContract {
    fn new(address: &str, path: String, account: &str, url: &str) -> Result<Self, Error> {
        Ok(Self::new(address, path, account, url)?)
    }

    // set (seed,signature(seed)) into the enigma smart contract
    fn set_worker_params(&self, eid: sgx_enclave_id_t, gas_limit : u64) -> Result<() ,Error> {
        Self::set_worker_params_internal(&self.w3_contract, &self.account, eid, gas_limit)
    }

    fn set_worker_params_internal(contract: &Contract<Http>, account: &Address, eid: sgx_enclave_id_t, gas_limit : u64) -> Result<(),Error>{

        // get seed,signature
        let (rand_seed, sig) = random_u::get_signed_random(eid);
        let the_seed : U256 = U256::from_big_endian(&rand_seed);
        println!("[---\u{25B6} seed: {} \u{25C0}---]",the_seed );
        // set gas options for the tx
        let mut options = Options::default();
        let mut gas : U256 = gas_limit.into();
        options.gas = Some(gas);

        // set random seed
        contract.call("setWorkersParams", (the_seed, sig.to_vec()), *account, options ).wait().unwrap();
        Ok(())
    }

    fn watch_blocks(&self, epoch_size : usize, polling_interval : u64, eid : sgx_enclave_id_t, gas_limit : u64, max_epochs : Option<usize>){
        
        let prev_epoch = Arc::new(AtomicUsize::new(0));
        let max_epochs = max_epochs.unwrap_or(0);
        let mut epoch_counter = 0;
        let w3_contract = Arc::new(self.w3_contract.clone());
        let account = Arc::new(self.account.clone());

        loop {
            let account_clone = Arc::clone(&account);
            let prev_epoch = Arc::clone(&prev_epoch);
            let w3_contract_clone = Arc::clone(&w3_contract);

            let future = self.web3.eth().block_number().and_then(move |num| {
                    let curr_block = num.low_u64() as usize;
                    let prev_block_ref = prev_epoch.load(Ordering::Relaxed);

                    if prev_block_ref == 0 || curr_block >= (prev_block_ref + epoch_size) {
                        prev_epoch.swap(curr_block, Ordering::Relaxed);

                        println!("[\u{1F50A} ] @ block {}, prev block @ {} [\u{1F50A} ]", curr_block, prev_block_ref);
                        EnigmaContract::set_worker_params_internal(&w3_contract_clone, &account_clone, eid, gas_limit);
                    }
                Ok(())
            });

            self.eloop.remote().spawn(|_| future.map_err(|err| eprintln!("Errored with: {:?}", err)));
            thread::sleep(time::Duration::from_secs(polling_interval));
            epoch_counter+=1;
            if max_epochs != 0 && epoch_counter == max_epochs{
                println!("[+] Principal: reached max_epochs {} , stopping.",max_epochs );
                break;
            }
        }
    }
}
