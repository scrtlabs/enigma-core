//pub mod primitives;
//pub mod dal;

use rocksdb::{ReadOptions, DBIterator, IteratorMode, Direction};
use rocksdb::DB as rocks_db;
use hex::{ToHex, FromHex};
use failure::Error;

use db::primitives::{DeltaKey, Stype, SplitKey};
use db::dal::{DB, CRUDInterface};
use common_u::errors::{DBErr, DBErrKind};

const DELTA_PREFIX: &[u8] = &[1];
type ContractAddress = [u8; 32];


pub trait P2PCalls<K,D>{
    /// return the latest delta for the required address.
    fn get_tip(&self, address: &ContractAddress) -> Result<(K, D),Error>;

    /// return the latest delta for each of the required addresses.
    fn get_tips(&self, address_list: &[ContractAddress]) -> Result<Vec<(K, D)>, Error>;

    /// get a list of all addresses in the DB.
    fn get_all_addresses(&self) -> Result<Vec<[u8; 32]>, Error>;

    /// get the delta of the required address and key.
    fn get_delta(&mut self, key: K) -> Result<Vec<u8>,Error>;

    /// get the contract of the required contract.
    fn get_contract(&mut self, address: ContractAddress) -> Result<Vec<u8>,Error>;

    /// returns a list of the latest deltas for all addresses.
    fn get_all_tips(&self) -> Result<Vec<(K, D)>, Error>;

    /// returns a list of all keys specified with their corresponding deltas.
    fn get_deltas(&self, addresses_range: Vec<(K, K)>) -> Result<Vec<Result<(K, D), Error>>, Error>;
}

impl<K: SplitKey> P2PCalls<K, Vec<u8>> for DB {

    fn get_tip(&self, address: &ContractAddress) -> Result<(K, Vec<u8>),Error> {
        // check and extract the CF from the DB
        // to_hex converts the [u8] to str
        let str_addr = address.to_hex();
        match self.database.cf_handle(&str_addr) {
            None => Err(DBErr { command: "get_tip".to_string(), kind: DBErrKind::MissingKey, previous: None }.into()),
            Some(cf_key) => {
                let iter = self.database.prefix_iterator_cf(cf_key, DELTA_PREFIX)?;
                match iter.last() {
                    None => Err(DBErr { command: "get_tip".to_string(), kind: DBErrKind::MissingKey, previous: None }.into()),
                    Some(last) => {
                        let dk = K::from_split(&str_addr, &*last.0)?;
                        Ok((dk, (&*last.1).to_vec()))
                    }
                }
            }
        }
    }

    fn get_tips(&self, address_list: &[ContractAddress]) -> Result<Vec<(K, Vec<u8>)>, Error> {
        let mut deltas_list = Vec::new();
        // todo: how will we know if there was an error??
        for address in address_list {
            deltas_list.push(self.get_tip(&address)?);
        }
        Ok(deltas_list)
    }

    fn get_all_addresses(&self) -> Result<Vec<ContractAddress>, Error> {
        // get a list of all CF's (addresses) in our DB
        let mut cf_list = rocks_db::list_cf(&self.options, &self.location)?;
        match cf_list.len() {
            // list_cf returns "Default" as the first CF,
            // so we remove it if we have elements other than that in the DB.
            l if l > 1 => cf_list.remove(0),
            _ => return Err(DBErr { command: "get_all_addresses".to_string(), kind: DBErrKind::MissingKey, previous: None }.into()),
        };
        // convert all addresses from strings to slices.
        Ok(cf_list.iter().filter_map(|address_str| {
            let mut address = [0u8; 32];
            let slice_address = match address_str.from_hex() {
                Ok(slice) => slice,
                Err(_) => return None
            };
            address.copy_from_slice(&slice_address[..]); // TODO: Handle this error
            Some(address)
        }).collect::<Vec<_>>())
    }

    fn get_delta(&mut self, key: K) -> Result<Vec<u8>, Error> {Ok(self.read(&key)?)}

    fn get_contract(&mut self, address: ContractAddress) -> Result<Vec<u8>, Error> {
        let key = DeltaKey{hash: address, key_type: Stype::ByteCode};
        Ok(self.read(&key)?)
    }

    fn get_all_tips(&self) -> Result<Vec<(K, Vec<u8>)>, Error> {

        let _address_list: Vec<ContractAddress> = match P2PCalls::<K, Vec<u8>>::get_all_addresses(self) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        self.get_tips(&_address_list[..])
    }

    // input: addresses_range : Vec<Tuple(K, K)> where K is usually a DeltaKey.
    // output: all keys & values from the first key (included!) up to the second key (not included!!)
    fn get_deltas(&self, addresses_range: Vec<(K, K)>) -> Result<Vec<Result<(K, Vec<u8>), Error>>, Error> {
        // a vector for the output values which will consist of tuples: (key: K, value/delta: D)
        let mut deltas_list: Vec<Result<(K, Vec<u8>), Error>> = Vec::new();
        // for each tuple in the input
        for address_rng in addresses_range.iter() {
//
            // convert the key to the needed rocksdb representation
            address_rng.0.as_split(|from_hash, from_key| -> Result<(), Error> {
                // make sure the address exists as a CF in the DB
                match self.database.cf_handle(&from_hash) {
                    None => Err(DBErr { command: "read".to_string(), kind: DBErrKind::MissingKey, previous: None }.into()),
                    Some(cf_key) => {
                        // if exists, extract the second key for the range.
                        address_rng.1.as_split(|hash_to, to_key| {
                            if hash_to == from_hash {
                                bail!("addresses of values are not equal {:?},{:?}",hash_to,from_hash);
                            }
                            let mut read = ReadOptions::default();
                            // add the key as an upper bound
                            // (all elements up to this key, not included!!)
                            read.set_iterate_upper_bound(&to_key);
                            // build an iterator which will iterate from the first key
                            let db_iter = DBIterator::new_cf(&self.database, cf_key.clone(), &read, IteratorMode::From(&from_key, Direction::Forward))?;
                            let k_iter = db_iter.map(|(key, val)| {
                                // creating from the string of the address and the
                                // key of each result in the iterator a K type.
                                // from_split returns a result and therefore will return
                                // an error in case that it won't be able to create the key.
                                Ok((K::from_split(hash_to, &*key)?, (&*val).to_vec() )) // TODO: Handle this error
                            });
                            //add the values received from the iteration
                            // of the input to the output vector.
                            let k_vec: Vec<Result< (K, Vec<u8>), Error >> = k_iter.collect();
                            deltas_list.extend(k_vec);
                            Ok(())
                        })
                    },
                }
            })?;
        }
        Ok(deltas_list)
    }
}

#[cfg(test)]
mod test {
    extern crate tempdir;

    use hex::ToHex;
    use failure::Error;
    use db::dal::{DB, CRUDInterface};
    use db::iterator::P2PCalls;
    use db::primitives::{SplitKey, DeltaKey, Array32u8};

    #[should_panic]
    #[test]
    fn test_get_tip_no_data() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [7u8; 32];
        let ( _key, _val ): ( DeltaKey, Vec<u8> ) = db.get_tip(&arr).unwrap();
    }

    #[should_panic]
    #[test]
    fn test_get_tip_data_no_delta() {
        let tempdir = tempdir::TempDir::new("enigma-core-test").unwrap().into_path();
        let mut db = DB::new(tempdir.clone(), true).unwrap();
        let arr = [7u8; 32];
        let v = b"Enigma";
        db.create(&Array32u8( arr ), &v[..]).unwrap();
        let ( _key, _val ): ( DeltaKey, Vec<u8> ) = db.get_tip(&arr).unwrap();
    }
}