extern crate principal;
extern crate web3;

use web3::Web3;
use principal::Ledger;
use principal::EpochGen;
use std::sync::Arc;

trait Emittable {
    fn new() -> Self;
    fn emit_epoch(&self, block: usize);
}

impl Emittable for EpochGen {
    fn new() -> Self {
        EpochGen {}
    }

    fn emit_epoch(&self, block: usize) {
        println!("emitting epoch: {}", block);
    }
}

fn main() {
    /// TODO: externalize to config
    let (eloop, http) = web3::transports::Http::new("http://localhost:9545")
        .expect("unable to create Web3 HTTP provider");
    let w3 = web3::Web3::new(http);

    let ledger = Ledger::new(w3);
    let eg = EpochGen::new();

    let epoch_generator = Arc::new(eg);
    ledger.watch_blocks(eloop, epoch_generator, 3);
}
