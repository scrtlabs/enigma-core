use failure::Error;
use hex::FromHex;
use std::sync::{Mutex, MutexGuard};
use tiny_keccak::Keccak;

pub trait LockExpectMutex<T> {
    fn lock_expect(&self, name: &str) -> MutexGuard<T>;
}

impl<T> LockExpectMutex<T> for Mutex<T> {
    fn lock_expect(&self, name: &str) -> MutexGuard<T> { self.lock().unwrap_or_else(|_| panic!("{} mutex is poison", name)) }
}

pub trait Sha256<T> {
    fn sha256(&self) -> T where T: Sized;
}

pub trait Keccak256<T> {
    fn keccak256(&self) -> T where T: Sized;
}

pub trait FromHex32<T> {
    fn from_hex_32(&self) -> T where T: Sized;
}

impl FromHex32<Result<[u8; 32], Error>> for str {
    fn from_hex_32(&self) -> Result<[u8; 32], Error> {
        let hex: Vec<u8> = self.from_hex()?;
        if hex.len() != 32 { bail!("Wrong length"); }
        let mut result = [0u8; 32];
        result.copy_from_slice(&hex);
        Ok(result)
    }
}

impl Keccak256<[u8; 32]> for [u8] {
    fn keccak256(&self) -> [u8; 32] {
        let mut keccak = Keccak::new_keccak256();
        let mut result = [0u8; 32];
        keccak.update(self);
        keccak.finalize(&mut result);
        result
    }
}

impl Sha256<[u8; 32]> for [u8] {
    fn sha256(&self) -> [u8; 32] {
        let mut hash = openssl::sha::Sha256::new();
        hash.update(self);
        hash.finish()
    }
}
