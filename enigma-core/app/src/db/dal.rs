use std::path::PathBuf;
use failure::Error;
use leveldb::options::{Options,WriteOptions,ReadOptions};
use leveldb::database::Database;
use leveldb::kv::KV;

pub struct DB {
    location: PathBuf,
    database: Database<i32>,
}

impl DB {
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
    fn new(path: PathBuf, create_if_missing: bool) -> Result<DB, Error> {
        let mut options = Options::new();
        options.create_if_missing = create_if_missing;
        let mut db = Database::open(path.as_path(), options)?;
        Ok( DB {
            location: path,
            database: db
        } )
    }
}

pub trait CRUDInterface {
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

#[cfg(test)]
mod test {
    extern crate tempdir;
    use db::dal::DB;
    use std::fs;

    #[test]
    fn test_new_db() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let db = DB::new(tempdir.clone(), true).unwrap();
        fs::remove_dir_all(tempdir).unwrap();
    }
}