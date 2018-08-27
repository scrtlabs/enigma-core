use std::path::PathBuf;
use failure::Error;
use leveldb::options::{Options,WriteOptions,ReadOptions};
use leveldb::database::Database;


pub struct DB<'a> {
    location: PathBuf,
    database: Database<T>,
    options: Options,
    read_opts: ReadOptions<'a, K>,
    write_opts: WriteOptions,


}

pub trait DBInterface {
    fn new(path: PathBuf, create_if_missing: boolean) -> DB;
    fn create(&mut self, key: &str, value: &[u8]) -> Result<(), Error>;
    fn read(&mut self, key: &str) -> Result<Vec<u8>, Error>;
    fn update(&mut self, key: &str, value: &[u8]) -> Result<(), Error>;
    fn delete(&mut self, key: &str) -> Result<(), Error>;
}