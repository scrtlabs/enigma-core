extern crate web3;
extern crate rustc_hex;
extern crate serde_json;

use web3::Web3;
use web3::transports::Http;
use std::time;
use std::thread;
use web3::futures::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct EpochGen {}

/// Trying to make this an abstraction so the implementation can be externalized but
/// I'm not having any luck passing a Trait to Arc
trait Emittable
{
    fn new() -> Self;
    fn emit_epoch(&self, block: usize);
}

impl Emittable for EpochGen
{
    fn new() -> Self {
        EpochGen {}
    }

    fn emit_epoch(&self, block: usize) {
        println!("emitting epoch: {}", block);
    }
}

pub struct Ledger {
    w3: Web3<Http>,
}

/// For operations on the Ethereum ledger
impl Ledger
{
    pub fn new(w3: Web3<Http>) -> Self
    {
        Ledger { w3 }
    }

    pub fn watch_blocks(&self, eloop: web3::transports::EventLoopHandle, epoch_generator: Arc<EpochGen>, max_rounds: usize) {
        let blocks_in_epoch: usize = 5;
        let block = Arc::new(AtomicUsize::new(0));
        for _ in 0..max_rounds {
            let block = Arc::clone(&block);
            let epoch_generator = epoch_generator.clone();
            let f = self.w3.eth().block_number().then(move |res| {
                match res {
                    Ok(n) => {
                        let cur_block = n.low_u64() as usize;
                        let ref_block = block.swap(cur_block, Ordering::Relaxed);
                        println!("the current block number: {}, ref block: {}", cur_block, ref_block);

                        if (ref_block == 0) | (ref_block + blocks_in_epoch <= cur_block) {
                            epoch_generator.emit_epoch(cur_block);
                        }
                    }
                    Err(e) => println!("Error: {:?}", e),
                }

                Ok(())
            });

            eloop.remote().spawn(|_| f);
            thread::sleep(time::Duration::from_secs(10));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (web3::transports::EventLoopHandle, Web3<Http>) {
        let (_eloop, http) = web3::transports::Http::new("http://localhost:9545")
            .expect("unable to create Web3 HTTP provider");
        let w3 = web3::Web3::new(http);
        (_eloop, w3)
    }

    #[test]
    fn it_watch_blocks() {
        let (eloop, w3) = setup();
        let ledger = Ledger::new(w3);
        let eg = EpochGen::new();

        let epoch_generator = Arc::new(eg);
        ledger.watch_blocks(eloop, epoch_generator, 3);
    }
}
