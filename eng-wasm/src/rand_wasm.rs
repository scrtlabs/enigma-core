// pub use pwasm_abi::types::*;
use super::*;

pub struct Rand;

impl Rand {
    pub fn gen_slice(slice: &mut [u8]) { unsafe { external::rand(slice.as_ptr(), slice.len() as u32) }; }
}

pub trait RandTypes<T> {
    /// generate a random number on the trusted side.
    fn gen() -> T;
}

impl RandTypes<U256> for Rand {
    fn gen() -> U256 {
        let mut r: [u8; 32] = [0u8; 32];
        Self::gen_slice(&mut r);
        U256::from_big_endian(&r)
    }
}

impl RandTypes<u8> for Rand {
    fn gen() -> u8 {
        let mut r: [u8; 1] = [0u8; 1];
        Self::gen_slice(&mut r);
        r[0]
    }
}

impl RandTypes<u16> for Rand {
    fn gen() -> u16 {
        let mut r: [u8; 2] = [0u8; 2];
        Self::gen_slice(&mut r);
        u16::from_be_bytes(r)
    }
}

impl RandTypes<u32> for Rand {
    fn gen() -> u32 {
        let mut r: [u8; 4] = [0u8; 4];
        Self::gen_slice(&mut r);
        u32::from_be_bytes(r)
    }
}

impl RandTypes<u64> for Rand {
    fn gen() -> u64 {
        let mut r: [u8; 8] = [0u8; 8];
        Self::gen_slice(&mut r);
        u64::from_be_bytes(r)
    }
}
