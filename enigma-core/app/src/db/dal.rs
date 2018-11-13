use std::path::PathBuf;
use failure::Error;
use rocksdb::DB as rocks_db;
use rocksdb::{Options, WriteOptions, SliceTransform};

use common_u::errors::{DBErr, DBErrKind};
use db::primitives::SplitKey;

// These are global variables for Reade/Write/Create Options
const SYNC: bool = true;

#[allow(dead_code)] // TODO: Remove in the future
pub struct DB {
    pub location: PathBuf,
    pub database: rocks_db,
    pub options: Options,
}

#[allow(dead_code)] // TODO: Remove in the future
impl DB {
    /// Constructs a new `DB<'a>`. with a db file accordingly.
    ///
    /// You need to pass a path for the location of the db file
    /// and as a default, it adds options with a flag which creates the file if missing
    ///
    /// This Supports all the CRUD operations
    /// # Examples
    /// ```
    /// let db = DB::new(PathBuf::from("/test/test.db", false);
    /// ```
    pub fn new(location: PathBuf, create_if_missing: bool) -> Result<DB, Error> {
        // number of bytes to take into considertion when looking for a similar prefix
        // would be helpful when querying the DB using iterators.
        let prefix_extractor = SliceTransform::create_fixed_prefix(1);
        let mut options = Options::default();
        options.create_if_missing(create_if_missing);
        options.set_prefix_extractor(prefix_extractor);
        let database = rocks_db::open(&options, location.as_path()).unwrap();
        let db_par = DB{location, database, options};
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
    /// This is the same as update but it will create the key if it doesn't exist.
    ///
    /// # Examples
    /// ```
    /// db.force_update("test", "abc".as_bytes()).unwrap();
    /// ```
    fn force_update(&mut self, key: K, value: V) -> Result<(), E>;

}

impl<'a, K: SplitKey> CRUDInterface<Error, &'a K, Vec<u8>, &'a [u8]> for DB {

    fn create(&mut self, key: &'a K, value: &'a [u8]) -> Result<(), Error> {
        key.as_split( | hash, index_key| {
            // creates the ColumnFamily and verifies that it doesn't already exist
            let cf_key = match self.database.create_cf(&hash, &self.options) {
                Ok(cf) => cf,
                Err(_) => {
                    // if the CF exists just retrieve it from the DB
                    self.database.cf_handle(&hash).unwrap()
                }
            };
            // verifies that the key inside the CF doesn't already exist
            match self.database.get_cf(cf_key.clone(), &index_key)? {
                Some(_) => Err(DBErr { command: format!("create"), kind: DBErrKind::KeyExists, previous: None }.into()),
                None => {
                    let mut write_options = WriteOptions::default();
                    write_options.set_sync(SYNC);
                    match self.database.put_cf_opt(cf_key, &index_key, &value, &write_options) {
                        Ok(_) => Ok(()),
                        Err(e) => Err(DBErr { command: "create".to_string(), kind: DBErrKind::CreateError, previous: Some(e.into()) }.into())
                    }
                }
            }
        })
    }

    fn read(&mut self, key: &'a K) -> Result<Vec<u8>, Error> {
        key.as_split( | hash, index_key| {
            match self.database.cf_handle(&hash) {
                None => Err(DBErr { command: "read".to_string(), kind: DBErrKind::MissingKey, previous: None }.into()),
                Some(cf_key) => {
                    match self.database.get_cf(cf_key.clone(), &index_key)? {
                        Some(data) => Ok(data.to_vec()),
                        None => Err(DBErr { command: "read".to_string(), kind: DBErrKind::MissingKey, previous: None }.into()),
                    }
                },
            }
        })
    }
//    todo: write tests that check the delta implementation and the Stype enum
    fn update(&mut self, key: &'a K, value: &'a [u8]) -> Result<(), Error> {
        key.as_split( | hash, index_key| {
            match self.database.cf_handle(&hash) {
                None => Err(DBErr { command: "update".to_string(), kind: DBErrKind::MissingKey, previous: None }.into()),
                Some(cf_key) => {
                    match self.database.get_cf(cf_key.clone(), &index_key)? {
                        None => Err(DBErr { command: "update".to_string(), kind: DBErrKind::MissingKey, previous: None }.into()),
                        Some(_) => {
                            let mut write_options = WriteOptions::default();
                            write_options.set_sync(SYNC);

                            match self.database.put_cf_opt(cf_key, &index_key, value, &write_options) {
                                Ok(_) => Ok(()),
                                Err(e) => Err(DBErr { command: "update".to_string(), kind: DBErrKind::UpdateError, previous: Some(e.into()) }.into())
                            }
                        },
                    }
                },
            }
        })
    }

    fn delete(&mut self, key: &'a K) -> Result<(), Error> {
        key.as_split( | hash, index_key| {
            match self.database.cf_handle(&hash) {
                // TODO: Write test that cf exist. but key doesn't, so this will fail.
                None => Err(DBErr { command: "delete".to_string(), kind: DBErrKind::MissingKey, previous: None }.into()),
                Some(cf_key) => {
                    match self.database.get_cf(cf_key.clone(), &index_key)? {
                        None => Err(DBErr { command: "delete".to_string(), kind: DBErrKind::MissingKey, previous: None }.into()),
                        Some(_) => {
                            self.database.delete_cf(cf_key, &index_key)?;
                            Ok(())
                        }
                    }
                }
            }
        })
    }

    fn force_update(&mut self, key: &'a K, value: &'a [u8]) -> Result<(), Error> {
        key.as_split( | hash, index_key| {
            match self.database.cf_handle(&hash) {
                // TODO: Write test that cf exist. but key doesn't, so this will fail.
                None => Err(DBErr { command: "update".to_string(), kind: DBErrKind::UpdateError, previous:None }.into()),
                Some(cf_key) => {
                    let mut write_options = WriteOptions::default();
                    write_options.set_sync(SYNC);

                    match self.database.put_cf_opt(cf_key, &index_key, value, &write_options) {
                        Ok(_) => Ok(()),
                        Err(e) => Err(DBErr { command: "update".to_string(), kind: DBErrKind::UpdateError, previous: Some(e.into()) }.into())
                    }
                }
            }
        })
    }

}

#[cfg(test)]
mod test {
    extern crate tempdir;
    use hex::ToHex;
    use db::dal::DB;
    use db::primitives::Array32u8;
    use db::dal::CRUDInterface;

    #[test]
    fn test_new_db() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let _db = DB::new(tempdir.clone(), true).unwrap();
    }

    #[test]
    fn test_create_read() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [7u8; 32];
        let v = b"Enigma";
        db.create(&Array32u8(arr), &v[..]).unwrap();
        assert_eq!(db.read(&Array32u8(arr)).unwrap(), v);
    }

    #[test]
    fn test_create_update_read() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [4u8; 32];
        let v = b"Enigma";
        db.create(&Array32u8( arr ), &v[..]).unwrap();
        assert_eq!(db.read(&Array32u8( arr )).unwrap(), v);
        let v = b"MPC";
        db.update(&Array32u8( arr ), &v[..]).unwrap();
        assert_eq!(db.read(&Array32u8( arr )).unwrap(), v);
    }

    #[test]
    fn test_create_when_cf_exists() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [3u8; 32];
        //created an empty cf in the DB
        let _cf = db.database.create_cf(&arr.to_hex(), &db.options).unwrap();
        let v = b"Enigma";
        db.create(&Array32u8( arr ), v).unwrap();
        assert_eq!(db.read(&Array32u8( arr )).unwrap(), v);
    }

    #[test]
    fn test_create_delete() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [5u8; 32];
        let v = b"Enigma";
        db.create(&Array32u8( arr ), &v[..]).unwrap();
        db.delete(&Array32u8( arr )).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_create_read_delete_fail_reading() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [9u8; 32];
        let v = b"Enigma";
        db.create(&Array32u8( arr ), &v[..]).unwrap();
        assert_eq!(db.read(&Array32u8( arr )).unwrap(), v);
        db.delete(&Array32u8( arr )).unwrap();
        db.read(&Array32u8( arr )).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_reading() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [2u8; 32];
        db.read(&Array32u8( arr )).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_cf_exists_no_key_read() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [3u8; 32];
        let _cf = db.database.create_cf(&arr.to_hex(), &db.options).unwrap();
        db.read(&Array32u8( arr )).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_updating() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [4u8; 32];
        db.update(&Array32u8( arr ), b"Enigma").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_updating_cf_exists() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [4u8; 32];
        let _cf = db.database.create_cf(&arr.to_hex(), &db.options).unwrap();
        db.update(&Array32u8( arr ), b"Enigma").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_deleting() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [7u8; 32];
        db.delete(&Array32u8( arr )).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_deleting_cf_exists() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [5u8; 32];
        let _cf = db.database.create_cf(&arr.to_hex(), &db.options).unwrap();
        db.delete(&Array32u8( arr )).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_creating_exist() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [8u8; 32];
        let v = b"Enigma";
        db.create(&Array32u8(arr), v).unwrap();
        assert_eq!(db.read(&Array32u8(arr)).unwrap(), v);
        db.create(&Array32u8(arr), v).unwrap();
    }
}