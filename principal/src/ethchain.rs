extern crate web3;
extern crate rustc_hex;

use self::web3::Web3;
use self::web3::transports::Http;
use self::web3::types::Address;
use std::time;
use std::thread;
use self::web3::futures::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct Ledger
{
    w3: Web3<Http>,
}

impl Ledger
{
    pub fn new(w3: Web3<Http>) -> Self
    {
        Ledger { w3 }
    }

    pub fn watch_blocks(&self, eloop: web3::transports::EventLoopHandle, blocks_in_epoch: usize, max_rounds: usize)
    {
        let block = Arc::new(AtomicUsize::new(0));
        for _ in 0..max_rounds {
            let block = Arc::clone(&block);
            let accounts = self.w3.eth().block_number().then(move |res| {
                match res {
                    Ok(n) => {
                        let cur_block = n.low_u64() as usize;
                        let ref_block = block.swap(cur_block, Ordering::Relaxed);
                        println!("the current block number: {}, ref block: {}", cur_block, ref_block);

                        if (ref_block == 0) | (ref_block + blocks_in_epoch <= cur_block) {
                            println!("new epoch")
                        }
                    }
                    Err(e) => println!("Error: {:?}", e),
                }

                Ok(())
            });
            eloop.remote().spawn(|_| accounts);
            thread::sleep(time::Duration::from_secs(10));
        }
    }
}

pub struct EnigmaContract
{
    w3: Web3<Http>,
    address: Address,
}

impl EnigmaContract
{
    pub fn new(w3: Web3<Http>, address: Address) -> Self
    {
        EnigmaContract { w3: w3, address: address }
    }
    pub fn register(&self) -> String
    {
        String::from("register")
    }
}


