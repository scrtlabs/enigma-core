use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time;

use failure::Error;
use web3::futures::Future;
use web3::types::U256;

use boot_network::epoch_provider::EpochProvider;
use enigma_tools_u::web3_utils::enigma_contract::EnigmaContract;
use enigma_tools_u::web3_utils::provider_types::EpochMarker;

// this trait should extend the EnigmaContract into Principal specific functions.
pub trait Principal {
    fn new(address: &str, path: String, account: &str, url: &str) -> Result<Self, Error>
        where Self: Sized;

    fn watch_blocks<G: Into<U256>>(&self, epoch_size: usize, polling_interval: u64, epoch_provider: Arc<EpochProvider>, gas_limit: G,
                                   confirmations: usize, max_epochs: Option<usize>);
}

impl Principal for EnigmaContract {
    fn new(address: &str, path: String, account: &str, url: &str) -> Result<Self, Error> {
        Ok(Self::from_deployed(address, path, Some(account), url)?)
    }

    fn watch_blocks<G: Into<U256>>(&self, epoch_size: usize, polling_interval: u64, epoch_provider: Arc<EpochProvider>, gas_limit: G,
                                   confirmations: usize, max_epochs: Option<usize>) {
        let gas_limit: U256 = gas_limit.into();
        let max_epochs = max_epochs.unwrap_or(0);
        let mut epoch_counter = 0;
        loop {
            let block_number = self.web3.eth().block_number().wait().unwrap();
            let curr_block = block_number.low_u64() as usize;
            let prev_block = match epoch_provider.get_marker() {
                Ok(marker) => {
                    match marker.confirmed_state {
                        Some(state) => state.block_number,
                        None => U256::from(0),
                    }
                }
                Err(_) => U256::from(0),
            };
            let prev_block_ref = prev_block.low_u64() as usize;
            println!("[\u{1F50A} ] Blocks @ previous: {}, current: {}, next: {} [\u{1F50A} ]", prev_block_ref, curr_block, (prev_block_ref + epoch_size));
            if prev_block_ref == 0 || curr_block >= (prev_block_ref + epoch_size) {
                println!("[\u{263C} ] New epoch found [\u{263C} ]");
                epoch_provider.set_worker_params(block_number, gas_limit, confirmations).expect("Unable to set worker params. Please recover manually.");
            } else {
                println!("[\u{23f3} ] Epoch still active [\u{23f3} ]");
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


