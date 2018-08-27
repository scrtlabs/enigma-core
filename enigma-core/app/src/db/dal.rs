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
    /// Constructs a new `DB<'a>`. with a db file accordingly.
    ///
    /// You need to pass a path for the db file
    /// and a flag to say if this should create the file if missing
    ///
    /// This Supports all the CRUD operations
    /// # Examples
    /// ```
    /// let db = DB::new(PathBuf::from("/test/test.db", false);
    /// ```
    fn new(path: PathBuf, create_if_missing: boolean) -> DB;
    /// Creates a new Key-Value pair
    ///
    /// # Examples
    /// ```
    /// db.create("test", "abc".as_bytes()).unwrap();
    /// ```
    fn create(&mut self, key: &str, value: &[u8]) -> Result<(), Error>; // TODO: Decide what to do if key doesn't exist
    /// Reads the Value in a specific Key
    ///
    /// # Examples
    /// ```
    /// let res = db.read("test").unwrap();
    /// assert_eq!("abc".as_bytes, res);
    /// ```
    fn read(&mut self, key: &str) -> Result<Vec<u8>, Error>;
    /// Updates an existing Key with a new value
    ///
    /// # Examples
    /// ```
    /// db.update("test", "abc".as_bytes()).unwrap();
    /// ```
    fn update(&mut self, key: &str, value: &[u8]) -> Result<(), Error>;
    /// Deletes an existing key
    ///
    /// # Examples
    /// ```
    /// db.delete("test").unwrap();
    /// ```
    fn delete(&mut self, key: &str) -> Result<(), Error>;
}