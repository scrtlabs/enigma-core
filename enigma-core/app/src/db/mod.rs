pub mod dal;
pub mod primitives;

use std::sync::Mutex;
pub use db::primitives::*;
use esgx::general::storage_dir;

lazy_static! {
    pub static ref DATABASE: Mutex< dal::DB<DeltaKey> > = {
        let enigma_dir = storage_dir();
        Mutex::new( dal::DB::new(enigma_dir, true).expect("Failed To initialize db in Mutex") )
    };
}