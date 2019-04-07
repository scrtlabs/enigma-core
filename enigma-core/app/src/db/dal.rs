use failure::Error;
use rocksdb::DB as rocks_db;
use rocksdb::{Options, SliceTransform, WriteOptions};
use std::path::{Path, PathBuf};

use common_u::errors::{DBErr, DBErrKind};
use db::primitives::SplitKey;

// These are global variables for Reade/Write/Create Options
const SYNC: bool = true;

pub struct DB {
    pub location: PathBuf,
    pub database: rocks_db,
    // the DB needs to store the options for creating new
    // cf's that would be able to imitate the DB behaviour
    pub options: Options,
}

impl DB {
    /// Constructs a new `DB`. with a db file accordingly.
    ///
    /// You need to pass a path for the location of the db file
    /// and as a default, it adds options with a flag which creates the file if missing
    ///
    /// This Supports all the CRUD operations
    /// # Examples
    /// ```
    /// # extern crate tempfile;
    /// # extern crate enigma_core_app;
    /// # use enigma_core_app::db::dal::DB;
    ///
    /// # let tempdir = tempfile::tempdir().unwrap();
    /// # let path = tempdir.path();
    /// let mut db = DB::new(path, true).unwrap();
    /// ```
    pub fn new<P: AsRef<Path>>(location: P, create_if_missing: bool) -> Result<DB, Error> {
        // number of bytes to take into consideration when looking for a similar prefix
        // would be helpful when querying the DB using iterators.
        let prefix_extractor = SliceTransform::create_fixed_prefix(1);
        let mut options = Options::default();
        options.create_if_missing(create_if_missing);
        options.set_prefix_extractor(prefix_extractor);
        // cf_list gets a list of all column families (addresses) from the location where the DB
        // is stored and when opening it, it adds the list as an argument to the DB. this is done
        // in case the DB existed, otherwise, an empty list will be added and the call will
        // be similar to a fresh start
        let cf_list = match rocks_db::list_cf(&options, &location) {
            Ok(list) => list,
            Err(_) => Vec::new(),
        };
        // converts the Strings to slices (str)
        let cf_list_burrowed = cf_list.iter().map(|i| i.as_str()).collect::<Vec<&str>>();
        let database = rocks_db::open_cf(&options, &location, &cf_list_burrowed[..])?;
        let location = location.as_ref().to_path_buf();
        let db_par = DB { location, database, options };
        Ok(db_par)
    }
}

pub trait CRUDInterface<E, K, T, V> {
    /// Creates a new Key-Value pair:
    /// # Examples
    /// ```
    /// # extern crate tempfile;
    /// # extern crate enigma_core_app;
    /// # use enigma_core_app::db::dal::{DB, CRUDInterface};
    /// # use enigma_core_app::db::primitives::Array32u8;
    ///
    /// # let tempdir = tempfile::tempdir().unwrap();
    /// # let mut db = DB::new(tempdir.path(), true).unwrap();
    /// # let key = Array32u8([7u8; 32]);
    /// let val = b"Enigma";
    /// db.create(&key, &val[..]).unwrap();
    ///  ```
    fn create(&mut self, key: K, value: V) -> Result<(), E>;
    // TODO: Decide what to do if key doesn't exist

    /// Reads the Value in a specific Key
    ///
    /// # Examples
    /// ```
    /// # extern crate tempfile;
    /// # extern crate enigma_core_app;
    /// # use enigma_core_app::db::dal::{DB, CRUDInterface};
    /// # use enigma_core_app::db::primitives::Array32u8;
    ///
    /// # let tempdir = tempfile::tempdir().unwrap();
    /// # let mut db = DB::new(tempdir.path(), true).unwrap();
    /// # let key = Array32u8([7u8; 32]);
    /// # let val = b"Enigma";
    /// # db.create(&key, &val[..]).unwrap();
    /// let res = db.read(&key).unwrap();
    /// assert_eq!(b"Enigma".to_vec(), res);
    /// ```
    fn read(&self, key: K) -> Result<T, E>;
    /// Updates an existing Key with a new value
    ///
    /// # Examples
    /// ```
    /// # extern crate tempfile;
    /// # extern crate enigma_core_app;
    /// # use enigma_core_app::db::dal::{DB, CRUDInterface};
    /// # use enigma_core_app::db::primitives::Array32u8;
    ///
    /// # let tempdir = tempfile::tempdir().unwrap();
    /// # let mut db = DB::new(tempdir.path(), true).unwrap();
    /// # let key = Array32u8([7u8; 32]);
    /// # let val = b"Enigma";
    /// # db.create(&key, &val[..]).unwrap();
    /// let new_val = b"protocol";
    /// db.update(&key, &new_val[..]).unwrap();
    /// assert_eq!(b"protocol".to_vec(), db.read(&key).unwrap());
    /// ```
    fn update(&mut self, key: K, value: V) -> Result<(), E>;
    /// Deletes an existing key
    ///
    /// # Examples
    /// ```should_panic
    /// # extern crate tempfile;
    /// # extern crate enigma_core_app;
    /// # use enigma_core_app::db::dal::{DB, CRUDInterface};
    /// # use enigma_core_app::db::primitives::Array32u8;
    ///
    /// # let tempdir = tempfile::tempdir().unwrap();
    /// # let mut db = DB::new(tempdir.path(), true).unwrap();
    /// # let key = Array32u8([7u8; 32]);
    /// # let val = b"Enigma";
    /// # db.create(&key, &val[..]).unwrap();
    /// db.delete(&key).unwrap();
    /// let no_val = db.read(&key).unwrap();
    ///
    ///  ```
    fn delete(&mut self, key: K) -> Result<(), E>;
    /// This is the same as update but it will create the key if it doesn't exist.
    ///
    /// # Examples
    /// ```
    /// # extern crate tempfile;
    /// # extern crate enigma_core_app;
    /// # use enigma_core_app::db::dal::{DB, CRUDInterface};
    /// # use enigma_core_app::db::primitives::Array32u8;
    ///
    /// # let tempdir = tempfile::tempdir().unwrap();
    /// # let mut db = DB::new(tempdir.path(), true).unwrap();
    /// # let key = Array32u8([7u8; 32]);
    /// # let val = b"Enigma";
    /// # db.create(&key, &val[..]).unwrap();
    /// let updated_val = b"EnigmaMPC";
    /// db.force_update(&key, &updated_val[..]).unwrap();
    /// assert_eq!(b"EnigmaMPC".to_vec(), db.read(&key).unwrap());
    fn force_update(&mut self, key: K, value: V) -> Result<(), E>;
}

impl<'a, K: SplitKey> CRUDInterface<Error, &'a K, Vec<u8>, &'a [u8]> for DB {

    #[logfn(DEBUG)]
    fn create(&mut self, key: &'a K, value: &'a [u8]) -> Result<(), Error> {
        key.as_split(|hash, index_key| {
            debug!("DB: Create: cf: {}, key: {:?}, value: {:?}", hash, index_key, value);
            // creates the ColumnFamily and verifies that it doesn't already exist
            let cf_key = match self.database.cf_handle(hash) {
                Some(cf) => cf,
                None => self.database.create_cf(hash, &self.options)?,
            };

            // verifies that the key inside the CF doesn't already exist
            match self.database.get_cf(cf_key, &index_key)? {
                Some(_) => Err(DBErr { command: "create".to_string(), kind: DBErrKind::KeyExists }.into()),
                None => {
                    let mut write_options = WriteOptions::default();
                    write_options.set_sync(SYNC);
                    self.database.put_cf_opt(cf_key, &index_key, &value, &write_options)?;
                    Ok(())
                }
            }
        })
    }

    #[logfn(DEBUG)]
    fn read(&self, key: &'a K) -> Result<Vec<u8>, Error> {
        key.as_split(|hash, index_key| {
            debug!("DB: Read: cf: {}, key: {:?}", hash, index_key);
            let cf_key = self.database.cf_handle(&hash).ok_or(DBErr { command: "read".to_string(), kind: DBErrKind::MissingKey })?;
            let value = self.database.get_cf(cf_key, &index_key)?.ok_or(DBErr { command: "read".to_string(), kind: DBErrKind::MissingKey })?;
            Ok(value.to_vec())
        })
    }

    #[logfn(DEBUG)]
    fn update(&mut self, key: &'a K, value: &'a [u8]) -> Result<(), Error> {
        key.as_split(|hash, index_key| {
            debug!("Updating DB: cf: {}, key: {:?}, value: {:?}", hash, index_key, value);
            let cf_key = self.database.cf_handle(&hash).ok_or(DBErr { command: "update".to_string(), kind: DBErrKind::MissingKey })?;

            if self.database.get_cf(cf_key, &index_key)?.is_none() {
                return Err(DBErr { command: "update".to_string(), kind: DBErrKind::MissingKey }.into());
            }

            let mut write_options = WriteOptions::default();
            write_options.set_sync(SYNC);
            self.database.put_cf_opt(cf_key, &index_key, value, &write_options)?;
            Ok(())
        })
    }

    #[logfn(DEBUG)]
    fn delete(&mut self, key: &'a K) -> Result<(), Error> {
        key.as_split(|hash, index_key| {
            debug!("DB: Delete: cf: {}, key: {:?}", hash, index_key);
            let cf_key = self.database.cf_handle(&hash).ok_or(DBErr { command: "delete".to_string(), kind: DBErrKind::MissingKey })?;

            if self.database.get_cf(cf_key, &index_key)?.is_none() {
                return Err(DBErr { command: "delete".to_string(), kind: DBErrKind::MissingKey }.into());
            }
            self.database.delete_cf(cf_key, &index_key)?;
            Ok(())
        })
    }

    #[logfn(DEBUG)]
    fn force_update(&mut self, key: &'a K, value: &'a [u8]) -> Result<(), Error> {
        key.as_split(|hash, index_key| {
            debug!("DB: Force Update: cf: {}, key: {:?}, value: {:?}", hash, index_key, value);
            // if the address does not exist, in force update, we would like to write it anyways.
            let cf_key = match self.database.cf_handle(hash) {
                Some(cf) => cf,
                None => self.database.create_cf(hash, &self.options)?,
            };
            let mut write_options = WriteOptions::default();
            write_options.set_sync(SYNC);
            self.database.put_cf_opt(cf_key, &index_key, value, &write_options)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod test {

    use crate::db::{tests::create_test_db, dal::CRUDInterface, primitives::{Array32u8, DeltaKey, Stype}};
    use hex::ToHex;

    #[test]
    fn test_new_db() {
        let (_db, _dir) = create_test_db();
    }

    #[test]
    fn test_create_read() {
        let (mut db, _dir) = create_test_db();

        let arr = [7u8; 32];
        let v = b"Enigma";
        db.create(&Array32u8(arr), &v[..]).unwrap();
        assert_eq!(db.read(&Array32u8(arr)).unwrap(), v);
    }

    #[test]
    fn test_create_update_read() {
        let (mut db, _dir) = create_test_db();

        let arr = [4u8; 32];
        let v = b"Enigma";
        db.create(&Array32u8(arr), &v[..]).unwrap();
        assert_eq!(db.read(&Array32u8(arr)).unwrap(), v);
        let v = b"MPC";
        db.update(&Array32u8(arr), &v[..]).unwrap();
        assert_eq!(db.read(&Array32u8(arr)).unwrap(), v);
    }

    #[test]
    fn test_create_update_read_delta() {
        let (mut db, _dir) = create_test_db();

        let contract_address = [4u8; 32].into();
        let key_type = Stype::Delta(3);
        let dk = DeltaKey { contract_address, key_type };
        let v = b"Enigma";

        db.create(&dk, &v[..]).unwrap();
        let v_updated = b"MPC";
        db.update(&dk, &v_updated[..]).unwrap();
        assert_eq!(db.read(&dk).unwrap(), v_updated);
    }

    #[test]
    fn test_create_when_cf_exists() {
        let (mut db, _dir) = create_test_db();

        let arr = [3u8; 32];
        //created an empty cf in the DB
        db.database.create_cf(&arr.to_hex(), &db.options).unwrap();
        let v = b"Enigma";
        db.create(&Array32u8(arr), v).unwrap();
        assert_eq!(db.read(&Array32u8(arr)).unwrap(), v);
    }

    #[test]
    fn test_create_delete() {
        let (mut db, _dir) = create_test_db();

        let arr = [5u8; 32];
        let v = b"Enigma";
        db.create(&Array32u8(arr), &v[..]).unwrap();
        db.delete(&Array32u8(arr)).unwrap();
    }

    #[test]
    fn test_force_update_no_cf_success() {
        let (mut db, _dir) = create_test_db();

        let arr = [4u8; 32];
        let val = b"Enigma";
        db.force_update(&Array32u8(arr), val).unwrap();
        let accepted_val = db.read(&Array32u8(arr)).unwrap();
        assert_eq!(accepted_val, val);
    }

    #[test]
    fn test_create_force_update_success() {
        let (mut db, _dir) = create_test_db();

        let arr = [4u8; 32];
        let val = b"Enigma";
        db.create(&Array32u8(arr), &val[..]).unwrap();
        let accepted_val = db.read(&Array32u8(arr)).unwrap();
        assert_eq!(accepted_val, val);

        let val_update = b"enigma_rocks";
        db.force_update(&Array32u8(arr), &val_update[..]).unwrap();
        let accepted_val = db.read(&Array32u8(arr)).unwrap();
        assert_eq!(accepted_val, val_update);
    }

    #[test]
    fn test_force_update_no_key_success() {
        let (mut db, _dir) = create_test_db();

        let contract_address = [4u8; 32].into();
        let key_type = Stype::Delta(1);
        let val = b"Enigma";
        db.create(&DeltaKey { contract_address, key_type }, &val[..]).unwrap();
        let accepted_val = db.read(&DeltaKey { contract_address, key_type }).unwrap();
        assert_eq!(accepted_val, val);

        // update a different delta
        let key_type = Stype::Delta(2);
        let val_update = b"enigma_rocks";
        db.force_update(&DeltaKey { contract_address, key_type }, &val_update[..]).unwrap();
        let accepted_val = db.read(&DeltaKey { contract_address, key_type }).unwrap();
        assert_eq!(accepted_val, val_update);
    }

    #[test]
    #[should_panic]
    fn test_create_read_delete_fail_reading() {
        let (mut db, _dir) = create_test_db();

        let arr = [9u8; 32];
        let v = b"Enigma";
        db.create(&Array32u8(arr), &v[..]).unwrap();
        assert_eq!(db.read(&Array32u8(arr)).unwrap(), v);
        db.delete(&Array32u8(arr)).unwrap();
        db.read(&Array32u8(arr)).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_reading() {
        let (db, _dir) = create_test_db();

        let arr = [2u8; 32];
        db.read(&Array32u8(arr)).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_cf_exists_no_key_read() {
        let (mut db, _dir) = create_test_db();

        let arr = [3u8; 32];
        let _cf = db.database.create_cf(&arr.to_hex(), &db.options).unwrap();
        db.read(&Array32u8(arr)).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_updating() {
        let (mut db, _dir) = create_test_db();

        let arr = [4u8; 32];
        db.update(&Array32u8(arr), b"Enigma").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_updating_cf_exists() {
        let (mut db, _dir) = create_test_db();

        let arr = [4u8; 32];
        db.database.create_cf(&arr.to_hex(), &db.options).unwrap();
        db.update(&Array32u8(arr), b"Enigma").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_deleting() {
        let (mut db, _dir) = create_test_db();

        let arr = [7u8; 32];
        db.delete(&Array32u8(arr)).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_deleting_cf_exists() {
        let (mut db, _dir) = create_test_db();

        let arr = [5u8; 32];
        db.database.create_cf(&arr.to_hex(), &db.options).unwrap();
        db.delete(&Array32u8(arr)).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_fail_creating_exist() {
        let (mut db, _dir) = create_test_db();

        let arr = [8u8; 32];
        let v = b"Enigma";
        db.create(&Array32u8(arr), v).unwrap();
        assert_eq!(db.read(&Array32u8(arr)).unwrap(), v);
        db.create(&Array32u8(arr), v).unwrap();
    }
}
