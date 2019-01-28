use failure::Error;
use hex::FromHex;
use std::sync::{Mutex, MutexGuard};

pub trait LockExpectMutex<T> {
    fn lock_expect(&self, name: &str) -> MutexGuard<T>;
}

impl<T> LockExpectMutex<T> for Mutex<T> {
    fn lock_expect(&self, name: &str) -> MutexGuard<T> { self.lock().unwrap_or_else(|_| panic!("{} mutex is poison", name)) }
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