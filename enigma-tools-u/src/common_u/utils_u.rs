use std::sync::{Mutex, MutexGuard};
use tiny_keccak::Keccak;

pub trait LockExpectMutex<T> {
    fn lock_expect(&self, name: &str) -> MutexGuard<T>;
}

impl<T> LockExpectMutex<T> for Mutex<T> {
    fn lock_expect(&self, name: &str) -> MutexGuard<T> {
        self.lock().expect(&format!("{} mutex is poison", name))
    }
}

pub trait Sha256<T> {
    fn sha256(&self) -> T where T: Sized;
}

pub trait Keccak256<T> {
    fn keccak256(&self) -> T where T: Sized;
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