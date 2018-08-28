use std::path::PathBuf;
use failure::Error;
use leveldb::options::{Options,WriteOptions,ReadOptions};
use leveldb::database::Database;
use leveldb::kv::KV;
use db_key::Key;
use common_u::errors;
use db::primitives::Array32u8;


pub struct DB<K: Key> {
    location: PathBuf,
    database: Database<K>,
}

impl<K: Key> DB<K> {
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
    pub fn new(path: PathBuf, create_if_missing: bool) -> Result<DB<K>, Error> {
        let mut options = Options::new();
        options.create_if_missing = create_if_missing;
        let mut db = Database::open(path.as_path(), options)?;
        let db_par = DB{
            location: path,
            database: db
        };
        Ok( db_par )
    }
}

pub trait CRUDInterface<E, K, T, V> {
    /// Creates a new Key-Value pair
    ///
    /// # Examples
    /// ```
    /// db.create("test", "abc".as_bytes()).unwrap();
    /// ```
    fn create(&mut self, key: K, value: V) -> Result<(), E>; // TODO: Decide what to do if key doesn't exist
    /// Reads the Value in a specific Key
    ///
    /// # Examples
    /// ```
    /// let res = db.read("test").unwrap();
    /// assert_eq!("abc".as_bytes, res);
    /// ```
    fn read(&mut self, key: K) -> Result<T, E>;
    /// Updates an existing Key with a new value
    ///
    /// # Examples
    /// ```
    /// db.update("test", "abc".as_bytes()).unwrap();
    /// ```
    fn update(&mut self, key: K, value: V) -> Result<(), E>;
    /// Deletes an existing key
    ///
    /// # Examples
    /// ```
    /// db.delete("test").unwrap();
    /// ```
    fn delete(&mut self, key: K) -> Result<(), E>;
}


impl<'a> CRUDInterface<Error, &'a [u8; 32], Vec<u8>, &'a [u8]> for DB<Array32u8> {

    fn create(&mut self, key: &'a [u8; 32], value: &'a [u8]) -> Result<(), Error> {
        let write_opts = WriteOptions::new();
        let k = Array32u8{bits: *key};
        if self.database.get(ReadOptions::new(), k)?.is_some() {
            return Err(errors::DBErr {
                command: "create".to_string(), message: "Key already exist".to_string()
            }.into())
        }

        Ok(())
    }
    fn read(&mut self, key: &'a [u8; 32]) -> Result<Vec<u8>, Error> {
        Ok(vec![])
    }

    fn update(&mut self, key: &'a [u8; 32], value: &'a [u8]) -> Result<(), Error> {
        let write_opts = WriteOptions::new();
        Ok(())
    }

    fn delete(&mut self, key: &'a [u8; 32]) -> Result<(), Error> {
        let write_opts = WriteOptions::new();
        Ok(())

    }

}

#[cfg(test)]
mod test {
    extern crate tempdir;
    use db::dal::DB;
    use std::fs;
    use db::primitives::Array32u8;

    #[test]
    fn test_new_db() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let db = DB::<Array32u8>::new(tempdir.clone(), true).unwrap();
        fs::remove_dir_all(tempdir).unwrap();
    }
}