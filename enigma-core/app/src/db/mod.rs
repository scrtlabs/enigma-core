pub mod dal;
pub mod iterator;
pub mod primitives;

pub use crate::db::primitives::*;
pub use crate::db::iterator::*;
pub use crate::db::dal::*;
use esgx::general::storage_dir;
use std::sync::Mutex;

lazy_static! {
    pub static ref DATABASE: Mutex<dal::DB> = {
        let enigma_dir = storage_dir();
        Mutex::new(dal::DB::new(enigma_dir, true).expect("Failed To initialize db in Mutex"))
    };
}
