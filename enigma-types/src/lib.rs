#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![deny(unused_extern_crates)]


pub mod traits;
mod types;
mod hash;

#[cfg(all(feature = "sgx", not(feature = "std")))]
use serde_sgx as serde;

#[cfg(not(feature = "sgx"))]
use serde_std as serde;

use crate::traits::SliceCPtr;
pub use crate::types::*;

pub unsafe fn write_ptr<T>(src: &[T], dst: *mut T, count: usize) {
    if src.len() > count {
        unimplemented!()
    }
    core::ptr::copy_nonoverlapping(src.as_c_ptr(), dst, src.len());
}
