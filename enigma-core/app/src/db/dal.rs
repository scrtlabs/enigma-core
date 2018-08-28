use std::path::PathBuf;
use failure::Error;
use leveldb::options::{Options,WriteOptions,ReadOptions};
use leveldb::database::Database;
use leveldb::kv::KV;
use db_key::Key;
use common_u::errors::DBErr;
use db::primitives::Array32u8;

// These are global variables for Reade/Write/Create Options
const PARANOID_CHECK: bool = true;
const VERIFY_CHECKSUMS: bool = true;
const SYNC: bool = true;

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
        options.paranoid_checks = PARANOID_CHECK;
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


impl<'a, K: Key> CRUDInterface<Error, &'a K, Vec<u8>, &'a [u8]> for DB<K> {

    fn create(&mut self, key: &'a K, value: &'a [u8]) -> Result<(), Error> {
        // This verifies that the key doesn't already exist.
        let mut read_opts = ReadOptions::new();
        read_opts.verify_checksums = VERIFY_CHECKSUMS;
        if self.database.get(read_opts, key)?.is_some() {
            return Err( DBErr { command: "create".to_string(), message: "Key already exist".to_string() }.into())
        }

        let mut write_opts = WriteOptions::new();
        write_opts.sync = SYNC;
        match self.database.put(write_opts, key, value) {
            Ok(_) => return Ok(()),
            Err(e) => return Err(DBErr { command: "create".to_string(), message: "Failed to create the key".to_string() }.into())
        };
    }
    fn read(&mut self, key: &'a K) -> Result<Vec<u8>, Error> {
        let mut read_opts = ReadOptions::new();
        read_opts.verify_checksums = VERIFY_CHECKSUMS;

        match self.database.get(read_opts, key)? {
            Some(data) => return Ok(data),
            None => return Err(DBErr { command: "get".to_string(), message: "Failed to fetch the data".to_string() }.into())
        }
    }

    fn update(&mut self, key: &'a K, value: &'a [u8]) -> Result<(), Error> {
        // Make sure the key already exists.
        let mut read_opts = ReadOptions::new();
        read_opts.verify_checksums = VERIFY_CHECKSUMS;
        if self.database.get(read_opts, key)?.is_none() {
            return Err(DBErr { command: "update".to_string(), message: "The Key doesn't exist".to_string() }.into())
        }
        else {
            let mut write_opts = WriteOptions::new();
            write_opts.sync = SYNC;
            match self.database.put(write_opts, key, value) {
                Ok(_) => return Ok(()),
                Err(e) => return Err(DBErr { command: "create".to_string(), message: "Failed to create the key".to_string() }.into())
            };
        }
    }

    fn delete(&mut self, key: &'a K) -> Result<(), Error> {
        // This verifies that the key really doesn't exist.
        let mut read_opts = ReadOptions::new();
        read_opts.verify_checksums = VERIFY_CHECKSUMS;
        if self.database.get(read_opts, key)?.is_none() {
            return Err( DBErr { command: "delete".to_string(), message: "Key Doesn't exist".to_string() }.into())
        }
        let mut write_opts = WriteOptions::new();
        write_opts.sync = SYNC;
        self.database.delete(write_opts, key)?;
        Ok(())

    }

}

#[cfg(test)]
mod test {
    extern crate tempdir;
    use db::dal::DB;
    use std::fs;
    use db::primitives::Array32u8;
    use db::dal::CRUDInterface;

    #[test]
    fn test_new_db() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let db = DB::<Array32u8>::new(tempdir.clone(), true).unwrap();
        fs::remove_dir_all(tempdir).unwrap();
    }

    #[test]
    fn test_create_read() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::<Array32u8>::new(tempdir.clone(), true).unwrap();
        fs::remove_dir_all(tempdir).unwrap();
        let mut arr = [0u8; 32];
        arr[0..3].clone_from_slice( &[1,2,3]);
        let v = b"Enigma";
        db.create(&Array32u8{bits:arr}, &v[..]).unwrap();
        assert_eq!(db.read(&Array32u8{bits:arr}).unwrap(), v);
    }

    #[test]
    fn test_create_update_read() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::<Array32u8>::new(tempdir.clone(), true).unwrap();
        fs::remove_dir_all(tempdir).unwrap();
        let mut arr = [0u8; 32];
        arr[0..3].clone_from_slice( &[1,2,3]);
        let v = b"Enigma";
        db.create(&Array32u8{bits:arr}, &v[..]).unwrap();
        assert_eq!(db.read(&Array32u8{bits:arr}).unwrap(), v);
        let v = b"MPC";
        db.update(&Array32u8{bits:arr}, &v[..]).unwrap();
        assert_eq!(db.read(&Array32u8{bits:arr}).unwrap(), v);
    }

    #[test]
    fn test_create_delete() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::<Array32u8>::new(tempdir.clone(), true).unwrap();
        fs::remove_dir_all(tempdir).unwrap();
        let mut arr = [0u8; 32];
        arr[0..3].clone_from_slice( &[1,2,3]);
        let v = b"Enigma";
        db.create(&Array32u8{bits:arr}, &v[..]).unwrap();
        db.delete(&Array32u8{bits:arr}).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_create_read_delete_fail_reading() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::<Array32u8>::new(tempdir.clone(), true).unwrap();
        fs::remove_dir_all(tempdir).unwrap();
        let mut arr = [0u8; 32];
        arr[0..3].clone_from_slice( &[1,2,3]);
        let v = b"Enigma";
        db.create(&Array32u8{bits:arr}, &v[..]).unwrap();
        assert_eq!(db.read(&Array32u8{bits:arr}).unwrap(), v);
        db.delete(&Array32u8{bits:arr}).unwrap();
        db.read(&Array32u8{bits:arr}).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_reading() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::<Array32u8>::new(tempdir.clone(), true).unwrap();
        fs::remove_dir_all(tempdir).unwrap();
        let mut arr = [0u8; 32];
        arr[0..3].clone_from_slice( &[1,2,3]);
        db.read(&Array32u8{bits:arr}).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_updating() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::<Array32u8>::new(tempdir.clone(), true).unwrap();
        fs::remove_dir_all(tempdir).unwrap();
        let mut arr = [0u8; 32];
        arr[0..3].clone_from_slice( &[1,2,3]);
        db.update(&Array32u8{bits:arr}, b"Enigma").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_deleting() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::<Array32u8>::new(tempdir.clone(), true).unwrap();
        fs::remove_dir_all(tempdir).unwrap();
        let mut arr = [0u8; 32];
        arr[0..3].clone_from_slice( &[1,2,3]);
        db.delete(&Array32u8{bits:arr}).unwrap();
    }
}