#![no_std]

mod types;
pub mod traits;

pub use crate::types::{EnclaveReturn, ResultToEnclaveReturn};
use crate::traits::SliceCPtr;

pub unsafe fn write_ptr<T>(src: &[T], dst: *mut T, count: usize) {
    if src.len() > count {
        unimplemented!()
    }
    core::ptr::copy_nonoverlapping(src.as_c_ptr(), dst, src.len());
}