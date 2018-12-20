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
use web3::contract::{Contract, Options, CallFuture};
use web3::types::{Address, U256, TransactionRequest, Bytes, H256};
use web3::transports::Http;
use web3::Transport;
// enigma modules 
use esgx::random_u;
use enigma_tools_u::web3_utils::enigma_contract::{EnigmaContract};

// this trait should extend the EnigmaContract into Principal specific functions.
pub trait Principal<G: Into<U256>> {
     fn new(address: &str, path: String, account: &str, url: &str) -> Result<Self, Error> where  Self: Sized;

     fn set_worker_params(&self,eid: sgx_enclave_id_t, gas_limit : G) -> CallFuture<H256, <Http as Transport>::Out>;

     fn set_worker_params_internal(contract: &Contract<Http>, account: &Address, eid: sgx_enclave_id_t, gas_limit : G) -> CallFuture<H256, <Http as Transport>::Out>;

     fn watch_blocks(&self, epoch_size: usize, polling_interval : u64, eid: sgx_enclave_id_t, gas_limit: G, max_epochs: Option<usize>);
}


impl<G: Into<U256>> Principal<G> for EnigmaContract {
    fn new(address: &str, path: String, account: &str, url: &str) -> Result<Self, Error> {
        Ok(Self::new(address, path, Some(account), url)?)
    }

    // set (seed,signature(seed)) into the enigma smart contract
    fn set_worker_params(&self, eid: sgx_enclave_id_t, gas_limit : G) -> CallFuture<H256, <Http as Transport>::Out> {
        Self::set_worker_params_internal(&self.w3_contract, &self.account, eid, gas_limit)
    }

    fn set_worker_params_internal(contract: &Contract<Http>, account: &Address, eid: sgx_enclave_id_t, gas_limit : G) -> CallFuture<H256, <Http as Transport>::Out> {

        // get seed,signature
        let (rand_seed, sig) = random_u::get_signed_random(eid);
        let the_seed : U256 = U256::from_big_endian(&rand_seed);
        println!("[---\u{25B6} seed: {} \u{25C0}---]",the_seed );
        // set gas options for the tx
        let mut options = Options::default();
        options.gas = Some(gas_limit.into());
        // set random seed
         contract.call("setWorkersParams", (the_seed, sig.to_vec()), *account, options )
    }

    fn watch_blocks(&self, epoch_size : usize, polling_interval : u64, eid : sgx_enclave_id_t, gas_limit : G, max_epochs : Option<usize>) {
        // Make Arcs to support passing the refrence to multiple futures.
        let prev_epoch = Arc::new(AtomicUsize::new(0));
        let w3_contract = Arc::new(self.w3_contract.clone());
        let account = Arc::new(self.account.clone());

        let gas_limit: U256 = gas_limit.into();
        let max_epochs = max_epochs.unwrap_or(0);
        let mut epoch_counter = 0;
        loop {
            // Clone these arcs to be moved into the future.
            let account_clone = Arc::clone(&account);
            let prev_epoch = Arc::clone(&prev_epoch);
            let w3_contract_clone = Arc::clone(&w3_contract);

            let future = self.web3.eth().block_number().and_then(move |num| {
                    let curr_block = num.low_u64() as usize;
                    let prev_block_ref = prev_epoch.load(Ordering::Relaxed);
                    println!("current block: {}, next: {}", curr_block, (prev_block_ref + epoch_size));
                    if prev_block_ref == 0 || curr_block >= (prev_block_ref + epoch_size) {
                        prev_epoch.swap(curr_block, Ordering::Relaxed);
                        thread::sleep(time::Duration::from_secs(2));
                        println!("[\u{1F50A} ] @ block {}, prev block @ {} [\u{1F50A} ]", curr_block, prev_block_ref);
                        return Ok(());
                    }
                    Err(web3::Error::from_kind(web3::ErrorKind::InvalidResponse("not the right block".to_string())))
            }).map_err(From::from)
                .and_then(move |_| {
                        EnigmaContract::set_worker_params_internal(&w3_contract_clone, &account_clone, eid, gas_limit)
                });

            self.eloop.remote().spawn(|_| future.map_err(|err| eprintln!("Errored with: {:?}", err)).map(|res| println!("Res: {:?}", res)));
            thread::sleep(time::Duration::from_secs(polling_interval));
            epoch_counter+=1;
            if max_epochs != 0 && epoch_counter == max_epochs {
                println!("[+] Principal: reached max_epochs {} , stopping.",max_epochs );
                break;
            }
        }
    }
}
