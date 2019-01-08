use failure::Error;
use hex::{FromHex, ToHex};
use rocksdb::DB as rocks_db;
use rocksdb::{DBIterator, Direction, IteratorMode, ReadOptions, WriteBatch};
use crate::km_u::ContractAddress;
use crate::common_u::errors::{DBErr, DBErrKind};
use crate::db::dal::{CRUDInterface, DB};
use crate::db::primitives::{DeltaKey, SplitKey, Stype};

const DELTA_PREFIX: &[u8] = &[1];

type ResultVec<T> = Result<Vec<T>, Error>;
pub type ResultTypeVec<T> = Result<ResultType<Vec<T>>, Error>;

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub enum ResultType<T> {
    Full(T),
    Partial(T),
    None,
}

impl<T> ResultType<T> {
    pub fn unwrap(self) -> T {
        match self {
            ResultType::Partial(val) | ResultType::Full(val) => val,
            ResultType::None => panic!("called `ResultType::unwrap()` on a `None` value"),
        }
    }

    pub fn is_none(&self) -> bool {
        match *self {
            ResultType::None => true,
            _ => false,
        }
    }
}


pub trait P2PCalls<V> {
    /// returns the latest delta for the required address.
    /// # Examples
    /// ```
    /// let contract_address: [u8; 32] = [2u8; 32];
    /// let latest_delta_key, latest_delta_value = db.get_tip(&contract_address).unwrap();
    ///
    ///
    /// let dk = DeltaKey{ hash: [2u8; 32], key_type: Stype::Delta(42) };
    /// let latest_delta_key, latest_delta_value = db.get_tip(&dk.hash).unwrap();
    /// ```
    fn get_tip<K: SplitKey>(&self, address: &ContractAddress) -> Result<(K, V), Error>;

    /// return the latest delta for each of the required addresses.
    /// # Examples
    /// ```
    /// let addresses: [[u8; 32]] = [[1u8; 32], [2u8; 32], [4u8; 32], [8u8; 32]];
    /// let deltas_vec = db.get_tips(&addresses).unwrap();
    /// ```
    fn get_tips<K: SplitKey>(&self, address_list: &[ContractAddress]) -> ResultVec<(K, V)>;

    /// get a list of all valid addresses in the DB.
    /// # Examples
    /// ```
    /// let addresses_vec: Vec<[u8; 32]> = db.get_all_addresses().unwrap();
    /// ```
    fn get_all_addresses(&self) -> ResultVec<ContractAddress>;

    /// get the delta of the required address and key.
    /// # Examples
    /// ```
    /// let dk = DeltaKey{ hash: [2u8; 32], key_type: Stype::Delta(42) };
    /// let delta_val = db.get_delta(&dk).unwrap();
    /// ```
    fn get_delta<K: SplitKey>(&self, key: K) -> ResultVec<u8>;

    /// get the contract of the required address.
    /// # Examples
    /// ```
    /// let dk = DeltaKey{ hash: [2u8; 32], key_type: Stype::ByteCode };
    /// let contract = "code".to_bytes();
    /// db.create(&dk, &contract);
    ///
    ///
    /// let contract_from_db = db.get_contract(&dk.hash).unwrap();
    /// ```
    fn get_contract(&self, address: ContractAddress) -> ResultVec<u8>;

    /// returns a list of the latest deltas for all addresses that exist in the DB.
    /// # Examples
    /// ```
    /// let deltas_vec = db.get_all_tips().unwrap();
    /// ```
    fn get_all_tips<K: SplitKey>(&self) -> ResultVec<(K, V)>;

    /// returns a list of all keys in the ranges specified with their corresponding deltas.
    /// the result will contain all of the deltas in each tuple range from the
    /// first key until (not included) the last key.
    /// # Examples
    /// ```
    /// let from_a = DeltaKey{ hash: [2u8; 32], key_type: Stype::Delta(12) };
    /// let to_a = DeltaKey{ hash: [2u8; 32], key_type: Stype::Delta(47) };
    ///
    /// let from_b = DeltaKey{ hash: [6u8; 32], key_type: Stype::Delta(56) };
    /// let to_b = DeltaKey{ hash: [6u8; 32], key_type: Stype::Delta(94) };
    ///
    /// let delta_keys: Vec<(DeltaKey,DeltaKey)> = vec![(from_a,to_a), (from_b, to_b)];
    ///
    /// let deltas_vec: Vec<Result<(DeltaKey, Vec<u8>), Error> = db.get_deltas(&delta_keys).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// In each tuple the DeltaKey's must contain similar hashes
    /// (as seen in the example above), otherwise an error will be returned
    fn get_deltas<K: SplitKey>(&self, from: K, to: K) -> ResultTypeVec<(K, V)>;

    /// Inserts a list of Key-Values into the DB in one atomic operation
    /// # Examples
    /// ```
    /// let a = DeltaKey{ hash: [2u8; 32], key_type: Stype::Delta(12) };
    /// let b = DeltaKey{ hash: [2u8; 32], key_type: Stype::Delta(47) };
    /// let data_a = vec![1,2,3,4];
    /// let data_b = vec![5,6,7,8];
    ///
    /// let results = db.insert_tuples(&[(a, &data_a), (b, &data_b)]);
    /// for res in results {
    ///     res.unwrap();
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// The result is a Vec of Results each one corresponds to each Key-Value
    /// If the whole atomic operation failed the vec will contain only the error of the operation.
    fn insert_tuples<K: SplitKey>(&mut self, key_vals: &[(K, V)]) -> Vec<Result<(), Error>>;
}

impl P2PCalls<Vec<u8>> for DB {
    fn get_tip<K: SplitKey>(&self, address: &ContractAddress) -> Result<(K, Vec<u8>), Error> {
        // check and extract the CF from the DB
        // to_hex converts the [u8] to str
        let str_addr = address.to_hex();
        let cf_key = self.database.cf_handle(&str_addr).ok_or(
            DBErr { command: "get_tip".to_string(), kind: DBErrKind::MissingKey })?;

        let iter = self.database.prefix_iterator_cf(cf_key, DELTA_PREFIX)?;
        let last = iter.last().ok_or(DBErr { command: "get_tip".to_string(), kind: DBErrKind::MissingKey })?;
        let k_key = K::from_split(&str_addr, &*last.0)?;
        Ok((k_key, (&*last.1).to_vec()))

    }

    fn get_tips<K: SplitKey>(&self, address_list: &[ContractAddress]) -> ResultVec<(K, Vec<u8>)> {
        let mut deltas_list = Vec::with_capacity(address_list.len());
        for address in address_list {
            deltas_list.push(self.get_tip(&address)?);
        }
        Ok(deltas_list)
    }

    /// get_all_addresses will return a list of all addresses that are valid.
    /// meaning if an address was'nt saved according to the hex format the function will ignore it.
    fn get_all_addresses(&self) -> Result<Vec<ContractAddress>, Error> {
        // get a list of all CF's (addresses) in our DB
        let mut cf_list = rocks_db::list_cf(&self.options, &self.location)?;
        match cf_list.len() {
            // list_cf returns "Default" as the first CF,
            // so we remove it if we have elements other than that in the DB.
            l if l > 1 => cf_list.remove(0),
            _ => return Err(DBErr { command: "get_all_addresses".to_string(), kind: DBErrKind::MissingKey }.into()),
        };
        // convert all addresses from strings to slices.
        // filter_map filters all None types from the iterator,
        // therefore we return Option type for each item in the closure
        let addr_list = cf_list.iter().filter_map(|address_str| {
            let mut address = [0u8; 32];
            let slice_address = match address_str.from_hex() {
                Ok(slice) => slice,
               // if the address is not a correct hex then it is not a correct address.
               Err(_) => return None,
            };
            address.copy_from_slice(&slice_address[..]);
           Some(address)
        }).collect::<Vec<_>>();

        Ok(addr_list)
    }

    fn get_delta<K: SplitKey>(&self, key: K) -> ResultVec<u8> { Ok(self.read(&key)?) }

    fn get_contract(&self, address: ContractAddress) -> ResultVec<u8> {
        let key = DeltaKey { hash: address, key_type: Stype::ByteCode };
        Ok(self.read(&key)?)
    }

    fn get_all_tips<K: SplitKey>(&self) -> ResultVec<(K, Vec<u8>)> {
        let _address_list: Vec<ContractAddress> = self.get_all_addresses()?;
        self.get_tips(&_address_list[..])
    }

    // input: addresses_range : [Tuple(K, K)] where K is usually a DeltaKey.
    // output: all keys & values from the first key (included!) up to the second key (not included!!)
    fn get_deltas<K: SplitKey>(&self, from: K, to: K) -> ResultTypeVec<(K, Vec<u8>)> {
        // a vector for the output values which will consist of tuples: (key: K, value/delta: D)
        // convert the key to the rocksdb representation
        from.as_split(|from_hash, from_key| {
            // make sure the address exists as a CF in the DB
            let cf_key = self.database.cf_handle(&from_hash).ok_or(DBErr { command: "read".to_string(), kind: DBErrKind::MissingKey, })?;

            // if exists, extract the second key for the range.
            to.as_split(|hash_to, to_key| {
                if hash_to != from_hash {
                    bail!("addresses of values are not equal {:?},{:?}", hash_to, from_hash);
                }
                let mut read_opts = ReadOptions::default();
                // add the key as an upper bound
                // (all elements up to this key, not included!!)
                read_opts.set_iterate_upper_bound(&to_key);
                // build an iterator which will iterate from the first key
                let db_iter = DBIterator::new_cf(&self.database,
                                                       cf_key,
                                                       &read_opts,
                                                       IteratorMode::From(&from_key, Direction::Forward))?;
                let key_val: Vec<(K, Vec<u8>)> = db_iter.map(|(key, val)| {
                    // creating from the string of the address and the
                    // key of each result in the iterator a K type.
                    // from_split returns a result and therefore will return
                    // an error in case that it wasn't able to create the key.
                    (K::from_split(hash_to, &*key).unwrap(), (&*val).to_vec()) // TODO: Handle this error
                }).collect();
                // add the values received from this loop to the output vector.

                if key_val.is_empty(){
                    return Ok(ResultType::None);
                }
                let mut full = false;
                if let Some(last) = key_val.last() {
                    full = last.0.as_split(|_, key1| from.as_split( |_, key2 | key1 == key2 ));
                }
                if full {
                    Ok(ResultType::Full(key_val))
                } else {
                    Ok(ResultType::Partial(key_val))
                }
            })
        })
    }


    fn insert_tuples<K: SplitKey>(&mut self, key_vals: &[(K, Vec<u8>)]) -> Vec<Result<(), Error>> {
        let mut res = Vec::with_capacity(key_vals.len());
        let mut batch = WriteBatch::default();
        for (key, val) in key_vals {
            let tmp_res = key.as_split(|cf_str, key_slice| -> Result<(), Error> {
                let cf = match self.database.cf_handle(cf_str) {
                    Some(cf) => cf,
                    None => self.database.create_cf(cf_str, &self.options)?,
                };
                batch.put_cf(cf, key_slice, val)?;
                Ok(())
            });
            res.push(tmp_res);
        }
        match self.database.write(batch) {
            Ok(_) => res,
            Err(e) => vec![Err(e.into())],
        }
    }
}

#[cfg(test)]
mod test {
    use crate::db::dal::{CRUDInterface, DB};
    use crate::db::iterator::{ContractAddress, P2PCalls};
    use crate::db::primitives::{DeltaKey, Stype};

    #[test]
    fn test_get_tip_multi_deltas_success() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();

        let hash = [7u8; 32];

        let key_type_a = Stype::Delta(1);
        let dk_a = DeltaKey { hash, key_type: key_type_a };
        let v_a = b"Enigma_a";

        let key_type_b = Stype::Delta(2);
        let dk_b = DeltaKey { hash, key_type: key_type_b };
        let v_b = b"Enigma_b";

        db.create(&dk_a, &v_a[..]).unwrap();
        db.create(&dk_b, &v_b[..]).unwrap();

        let (accepted_key, accepted_val): (DeltaKey, Vec<u8>) = db.get_tip(&hash).unwrap();
        assert_eq!(accepted_key, dk_b);
        assert_eq!(accepted_val, v_b);
    }

    #[test]
    fn test_get_tip_success() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();

        let hash = [7u8; 32];
        let key_type = Stype::Delta(23);
        let dk = DeltaKey { hash, key_type };
        let v = b"Enigma";

        db.create(&dk, &v[..]).unwrap();
        let (accepted_key, accepted_val): (DeltaKey, Vec<u8>) = db.get_tip(&hash).unwrap();

        assert_eq!(accepted_key, dk);
        assert_eq!(accepted_val, v);
    }

    #[should_panic]
    #[test]
    fn test_get_tip_no_data() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let db = DB::new(&tempdir, true).unwrap();
        let arr = [7u8; 32];
        let (_key, _val): (DeltaKey, Vec<u8>) = db.get_tip(&arr).unwrap();
    }

    #[should_panic]
    #[test]
    fn test_get_tip_data_no_delta() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();
        let hash = [7u8; 32];
        let key_type = Stype::State;
        let dk = DeltaKey { hash, key_type };
        let v = b"Enigma";
        db.create(&dk, &v[..]).unwrap();
        let (_key, _val): (DeltaKey, Vec<u8>) = db.get_tip(&hash).unwrap();
    }

    #[test]
    fn test_get_tips_single_row_success() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();

        let hash = [7u8; 32];
        let key_type = Stype::Delta(23);
        let dk = DeltaKey { hash, key_type };
        let v = b"Enigma";

        db.create(&dk, &v[..]).unwrap();
        let accepted_tips: Vec<(DeltaKey, Vec<u8>)> = db.get_tips(&[hash]).unwrap();

        assert_eq!(accepted_tips[0].0, dk);
        assert_eq!(accepted_tips[0].1, v);
    }

    #[test]
    fn test_get_tips_multi_row_per_add_success() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();
        let hash = [7u8; 32];

        let key_type_a = Stype::Delta(1);
        let dk_a = DeltaKey { hash, key_type: key_type_a };
        let v_a = b"Enigma_a";

        let key_type_b = Stype::Delta(2);
        let dk_b = DeltaKey { hash, key_type: key_type_b };
        let v_b = b"Enigma_b";

        db.create(&dk_a, &v_a[..]).unwrap();
        db.create(&dk_b, &v_b[..]).unwrap();
        let accepted_tips: Vec<(DeltaKey, Vec<u8>)> = db.get_tips(&[hash]).unwrap();
        assert_eq!(accepted_tips[0].0, dk_b);
        assert_eq!(accepted_tips[0].1, v_b);
    }

    #[test]
    fn test_get_tips_multi_add_success() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();

        let hash_a = [7u8; 32];
        let key_type_a = Stype::Delta(1);
        let dk_a = DeltaKey { hash: hash_a, key_type: key_type_a };
        let v_a = b"Enigma_a";

        let hash_b = [4u8; 32];

        let key_type_b = Stype::Delta(2);
        let dk_b = DeltaKey { hash: hash_b, key_type: key_type_b };
        let v_b = b"Enigma_b";

        let key_type_c = Stype::State;
        let dk_c = DeltaKey { hash: hash_b, key_type: key_type_c };
        let v_c = b"Enigma_rules";

        db.create(&dk_a, &v_a[..]).unwrap();
        db.create(&dk_b, &v_b[..]).unwrap();
        db.create(&dk_c, &v_c[..]).unwrap();

        let accepted_tips: Vec<(DeltaKey, Vec<u8>)> = db.get_tips(&[hash_a, hash_b]).unwrap();
        assert_eq!(accepted_tips[0].1, v_a);
        assert_eq!(accepted_tips[1].1, v_b);
    }

    #[should_panic]
    #[test]
    fn test_get_tips_no_addr() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();

        let hash_a = [7u8; 32];
        let key_type_a = Stype::Delta(1);
        let dk_a = DeltaKey { hash: hash_a, key_type: key_type_a };
        let v_a = b"Enigma_a";

        let hash_b = [4u8; 32];

        db.create(&dk_a, &v_a[..]).unwrap();

        let _accepted_tips: Vec<(DeltaKey, Vec<u8>)> = db.get_tips(&[hash_a, hash_b]).unwrap();
    }

    #[should_panic]
    #[test]
    fn test_get_tips_no_deltas() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();

        let hash_a = [7u8; 32];
        let key_type_a = Stype::State;
        let dk_a = DeltaKey { hash: hash_a, key_type: key_type_a };
        let v_a = b"Enigma_a";

        let hash_b = [4u8; 32];
        let key_type_b = Stype::ByteCode;
        let dk_b = DeltaKey { hash: hash_b, key_type: key_type_b };
        let v_b = b"Enigma_b";

        db.create(&dk_a, &v_a[..]).unwrap();
        db.create(&dk_b, &v_b[..]).unwrap();

        let _accepted_tips: Vec<(DeltaKey, Vec<u8>)> = db.get_tips(&[hash_a, hash_b]).unwrap();
    }

    #[test]
    fn test_get_all_addresses_success() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();

        let hash_a = [7u8; 32];
        let key_type_a = Stype::State;
        let dk_a = DeltaKey { hash: hash_a, key_type: key_type_a };
        let v_a = b"Enigma_state_1";

        let hash_b = [4u8; 32];
        let key_type_b = Stype::ByteCode;
        let dk_b = DeltaKey { hash: hash_b, key_type: key_type_b };
        let v_b = b"Enigma_byte_code_2";

        let hash_c = [67u8; 32];
        let key_type_c = Stype::Delta(78);
        let dk_c = DeltaKey { hash: hash_c, key_type: key_type_c };
        let v_c = b"Enigma_delta_3";

        let expected_addresses = vec![hash_a, hash_b, hash_c];

        db.create(&dk_a, &v_a[..]).unwrap();
        db.create(&dk_b, &v_b[..]).unwrap();
        db.create(&dk_c, &v_c[..]).unwrap();

        let accepted_addresses: Vec<ContractAddress> = db.get_all_addresses().unwrap();
        assert_eq!(expected_addresses, accepted_addresses);
    }

    #[test]
    fn test_get_all_addresses_invalid_cf() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();

        let hash_a = [7u8; 32];
        let key_type_a = Stype::State;
        let dk_a = DeltaKey { hash: hash_a, key_type: key_type_a };
        let v_a = b"Enigma_state_1";

        let hash_b = [4u8; 32];
        let key_type_b = Stype::ByteCode;
        let dk_b = DeltaKey { hash: hash_b, key_type: key_type_b };
        let v_b = b"Enigma_byte_code_2";

        let hash_c = [67u8; 32];
        let key_type_c = Stype::Delta(78);
        let dk_c = DeltaKey { hash: hash_c, key_type: key_type_c };
        let v_c = b"Enigma_delta_3";

        db.create(&dk_a, &v_a[..]).unwrap();
        db.create(&dk_b, &v_b[..]).unwrap();
        db.create(&dk_c, &v_c[..]).unwrap();

        let cf_str = "hello";

        let expected_addresses = vec![hash_a, hash_b, hash_c];

        let _cf = db.database.create_cf(&cf_str, &db.options).unwrap();

        let accepted_addresses: Vec<ContractAddress> = db.get_all_addresses().unwrap();

        assert_eq!(expected_addresses, accepted_addresses);
    }

    #[test]
    fn test_get_all_tips() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();

        let hash_a = [7u8; 32];
        let key_type_a = Stype::Delta(1);
        let dk_a = DeltaKey { hash: hash_a, key_type: key_type_a };
        let v_a = b"Enigma_a";

        let hash_b = [4u8; 32];

        let key_type_b = Stype::Delta(2);
        let dk_b = DeltaKey { hash: hash_b, key_type: key_type_b };
        let v_b = b"Enigma_b";

        let key_type_c = Stype::State;
        let dk_c = DeltaKey { hash: hash_b, key_type: key_type_c };
        let v_c = b"Enigma_rules";

        let key_type_d = Stype::Delta(3);
        let dk_d = DeltaKey { hash: hash_b, key_type: key_type_d };
        let v_d = b"r";

        let hash_e = [98u8; 32];
        let key_type_e = Stype::Delta(1);
        let dk_e = DeltaKey { hash: hash_e, key_type: key_type_e };
        let v_e = b"delta";

        db.create(&dk_a, &v_a[..]).unwrap();
        db.create(&dk_b, &v_b[..]).unwrap();
        db.create(&dk_c, &v_c[..]).unwrap();
        db.create(&dk_d, &v_d[..]).unwrap();
        db.create(&dk_e, &v_e[..]).unwrap();

        let accepted_tips: Vec<(DeltaKey, Vec<u8>)> = db.get_all_tips().unwrap();
        assert_eq!(accepted_tips.len(), 3);
    }

    #[test]
    fn test_get_deltas() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();

        let hash = [7u8; 32];

        let key_type_a = Stype::Delta(1);
        let dk_a = DeltaKey { hash, key_type: key_type_a };
        let v_a = b"Enigma";

        let key_type_b = Stype::Delta(2);
        let dk_b = DeltaKey { hash, key_type: key_type_b };
        let v_b = b"to";

        let key_type_c = Stype::Delta(3);
        let dk_c = DeltaKey { hash, key_type: key_type_c };
        let v_c = b"da";

        let key_type_d = Stype::Delta(4);
        let dk_d = DeltaKey { hash, key_type: key_type_d };
        let v_d = b"moon";

        let key_type_e = Stype::Delta(5);
        let dk_e = DeltaKey { hash, key_type: key_type_e };
        let v_e = b"and";

        let key_type_f = Stype::Delta(6);
        let dk_f = DeltaKey { hash, key_type: key_type_f };
        let v_f = b"back";

        db.create(&dk_a, &v_a[..]).unwrap();
        db.create(&dk_b, &v_b[..]).unwrap();
        db.create(&dk_c, &v_c[..]).unwrap();
        db.create(&dk_d, &v_d[..]).unwrap();
        db.create(&dk_e, &v_e[..]).unwrap();
        db.create(&dk_f, &v_f[..]).unwrap();

        let accepted_deltas = db.get_deltas(dk_a, dk_f).unwrap().unwrap();

        assert_eq!(accepted_deltas.len(), 5);
        let _deltas_iter = accepted_deltas.iter().map(|item| {
            if item.0 == dk_c {
                assert_eq!(item.1, v_c.to_vec());
            } else if item.0 == dk_e {
                assert_eq!(item.1, v_e.to_vec());
            };
        });
    }

    #[should_panic]
    #[test]
    fn test_get_deltas_different_hashes() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();

        let hash_a = [9u8; 32];
        let key_type_a = Stype::Delta(1);
        let dk_a = DeltaKey { hash: hash_a, key_type: key_type_a };
        let value = b"hash_a";

        let hash_b = [7u8; 32];
        let key_type_b = Stype::Delta(2);
        let dk_b = DeltaKey { hash: hash_b, key_type: key_type_b };

        db.create(&dk_a, &value[..]).unwrap();
        db.create(&dk_b, &value[..]).unwrap();

        match db.get_deltas(dk_a, dk_b) {
            Err(e) => {
                if format!("{:?}", e).contains("addresses of values are not equal") {
                    panic!(e);
                }
            },
            Ok(_) => (),
        }
    }

    #[test]
    fn test_insert_tuples() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap();
        let mut db = DB::new(&tempdir, true).unwrap();
        let data = vec![
            (DeltaKey { hash: [7u8; 32], key_type: Stype::Delta(1) }, b"Enigma".to_vec()),
            (DeltaKey { hash: [7u8; 32], key_type: Stype::Delta(2) }, b"to".to_vec()),
            (DeltaKey { hash: [7u8; 32], key_type: Stype::Delta(3) }, b"da".to_vec()),
            (DeltaKey { hash: [6u8; 32], key_type: Stype::Delta(4) }, b"moon".to_vec()),
            (DeltaKey { hash: [6u8; 32], key_type: Stype::Delta(5) }, b"and".to_vec()),
            (DeltaKey { hash: [6u8; 32], key_type: Stype::Delta(6) }, b"back".to_vec()),
    ];
        let results = db.insert_tuples(&data);
        for res in results {
            res.unwrap();
        }
        for (key, val) in data {
            assert_eq!(db.read(&key).unwrap(), val);
        }
    }

}
