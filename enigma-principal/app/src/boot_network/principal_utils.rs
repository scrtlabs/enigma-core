use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time;

// general
use failure::Error;
use sgx_types::sgx_enclave_id_t;
use web3::contract::{CallFuture, Contract};
use web3::futures::Future;
use web3::Transport;
use web3::transports::Http;
use web3::types::{Address, H256, U256};

use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
use boot_network::epoch_provider::EpochProvider;


// this trait should extend the EnigmaContract into Principal specific functions.
pub trait Principal {
    fn new(address: &str, path: String, account: &str, url: &str) -> Result<Self, Error>
        where Self: Sized;

    fn watch_blocks<G: Into<U256>>(&self, epoch_size: usize, polling_interval: u64, epoch_provider: Arc<EpochProvider>, gas_limit: G,
                                   max_epochs: Option<usize>);
}

impl Principal for EnigmaContract {
    fn new(address: &str, path: String, account: &str, url: &str) -> Result<Self, Error> {
        Ok(Self::from_deployed(address, path, Some(account), url)?)
    }

    fn watch_blocks<G: Into<U256>>(&self, epoch_size: usize, polling_interval: u64, epoch_provider: Arc<EpochProvider>, gas_limit: G,
                                   max_epochs: Option<usize>) {
        // Make Arcs to support passing the refrence to multiple futures.
        let prev_epoch = Arc::new(AtomicUsize::new(0));
        let w3_contract = Arc::new(self.w3_contract.clone());
        let account = Arc::new(self.account.clone());

        let gas_limit: U256 = gas_limit.into();
        let max_epochs = max_epochs.unwrap_or(0);
        let mut epoch_counter = 0;
        // TODO: Consider subscribing to block header instead of a loop like this: https://github.com/tomusdrw/rust-web3/blob/52cb309c951467625c201a9274ba0d7d739ebb3c/src/api/eth_subscribe.rs
        loop {
            // Clone these arcs to be moved into the future.
            let account = Arc::clone(&account);
            let prev_epoch = Arc::clone(&prev_epoch);
            let w3_contract = Arc::clone(&w3_contract);

            let num = self.web3.eth().block_number().wait().unwrap();
            let curr_block = num.low_u64() as usize;
            let prev_block_ref = prev_epoch.load(Ordering::Relaxed);
            println!("[\u{1F50A} ] Blocks @ previous: {}, current: {}, next: {} [\u{1F50A} ]", prev_block_ref, curr_block, (prev_block_ref + epoch_size));
            //TODO: Account for the fact that starting the app does not restart the chain
            if prev_block_ref == 0 || curr_block >= (prev_block_ref + epoch_size) {
                prev_epoch.swap(curr_block, Ordering::Relaxed);
                println!("New epoch found");
                match epoch_provider.set_worker_params(num, gas_limit) {
                    Ok(tx) => println!("Setting workers params with tx: {:?}", tx),
                    Err(err) => println!("Unable to set workers params: {:?}", err),
                }
            } else {
                println!("Epoch still active");
            }
            thread::sleep(time::Duration::from_secs(polling_interval));
            epoch_counter += 1;
            if max_epochs != 0 && epoch_counter == max_epochs {
                println!("[+] Principal: reached max_epochs {} , stopping.", max_epochs);
                break;
            }
        }
    }
}


