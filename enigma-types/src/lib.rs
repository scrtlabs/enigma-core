#![no_std]

pub mod traits;
mod types;

use crate::traits::SliceCPtr;
pub use crate::types::{EnclaveReturn, ResultToEnclaveReturn, ExecuteResult};

pub unsafe fn write_ptr<T>(src: &[T], dst: *mut T, count: usize) {
    if src.len() > count {
        unimplemented!()
    }
    core::ptr::copy_nonoverlapping(src.as_c_ptr(), dst, src.len());
}
