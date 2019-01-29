use std::sync::{Mutex, MutexGuard};

pub trait LockExpectMutex<T> {
    fn lock_expect(&self, name: &str) -> MutexGuard<T>;
}

impl<T> LockExpectMutex<T> for Mutex<T> {
    fn lock_expect(&self, name: &str) -> MutexGuard<T> { self.lock().unwrap_or_else(|_| panic!("{} mutex is poison", name)) }
}